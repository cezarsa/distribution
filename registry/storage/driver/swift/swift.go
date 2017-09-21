// Package swift provides a storagedriver.StorageDriver implementation to
// store blobs in Openstack Swift object storage.
//
// This package leverages the ncw/swift client library for interfacing with
// Swift.
//
// It supports both TempAuth authentication and Keystone authentication
// (up to version 3).
//
// As Swift has a limit on the size of a single uploaded object (by default
// this is 5GB), the driver makes use of the Swift Large Object Support
// (http://docs.openstack.org/developer/swift/overview_large_objects.html).
// Only one container is used for both manifests and data objects. Manifests
// are stored in the 'files' pseudo directory, data objects are stored under
// 'segments'.
package swift

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/ncw/swift"

	"github.com/docker/distribution/context"
	storagedriver "github.com/docker/distribution/registry/storage/driver"
	"github.com/docker/distribution/registry/storage/driver/base"
	"github.com/docker/distribution/registry/storage/driver/factory"
	"github.com/docker/distribution/version"
)

const driverName = "swift"

// defaultChunkSize defines the default size of a segment
const defaultChunkSize = 20 * 1024 * 1024

// minChunkSize defines the minimum size of a segment
const minChunkSize = 1 << 20

// contentType defines the Content-Type header associated with stored segments
const contentType = "application/octet-stream"

const (
	largeObjectTypeDLO = "DLO"
	largeObjectTypeSLO = "SLO"
)

const (
	// waitAfterMoveTimeout defines the time we wait before an object returns 404 after having been moved
	waitAfterMoveTimeout = 15 * time.Second

	// waitAfterMoveWait defines the time to sleep between two retries
	waitAfterMoveWait = 200 * time.Millisecond
)

// Parameters A struct that encapsulates all of the driver parameters after all values have been set
type Parameters struct {
	Username            string
	Password            string
	AuthURL             string
	Tenant              string
	TenantID            string
	Domain              string
	DomainID            string
	TenantDomain        string
	TenantDomainID      string
	TrustID             string
	Region              string
	AuthVersion         int
	Container           string
	Prefix              string
	EndpointType        string
	InsecureSkipVerify  bool
	ChunkSize           int
	SecretKey           string
	AccessKey           string
	TempURLContainerKey bool
	TempURLMethods      []string
	LargeObjectType     string
}

// swiftInfo maps the JSON structure returned by Swift /info endpoint
type swiftInfo struct {
	Swift struct {
		Version string `mapstructure:"version"`
	}
	Tempurl struct {
		Methods []string `mapstructure:"methods"`
	}
	BulkDelete struct {
		MaxDeletesPerRequest int `mapstructure:"max_deletes_per_request"`
	} `mapstructure:"bulk_delete"`
}

func init() {
	factory.Register(driverName, &swiftDriverFactory{})
}

// swiftDriverFactory implements the factory.StorageDriverFactory interface
type swiftDriverFactory struct{}

func (factory *swiftDriverFactory) Create(parameters map[string]interface{}) (storagedriver.StorageDriver, error) {
	return FromParameters(parameters)
}

type driver struct {
	Conn                 *swift.Connection
	Container            string
	Prefix               string
	BulkDeleteSupport    bool
	BulkDeleteMaxDeletes int
	ChunkSize            int
	SecretKey            string
	AccessKey            string
	TempURLContainerKey  bool
	TempURLMethods       []string
	LargeObjectType      string
}

type baseEmbed struct {
	base.Base
}

// Driver is a storagedriver.StorageDriver implementation backed by Openstack Swift
// Objects are stored at absolute keys in the provided container.
type Driver struct {
	baseEmbed
}

// FromParameters constructs a new Driver with a given parameters map
// Required parameters:
// - username
// - password
// - authurl
// - container
func FromParameters(parameters map[string]interface{}) (*Driver, error) {
	params := Parameters{
		ChunkSize:          defaultChunkSize,
		InsecureSkipVerify: false,
	}

	if err := mapstructure.Decode(parameters, &params); err != nil {
		return nil, err
	}

	if params.Username == "" {
		return nil, fmt.Errorf("No username parameter provided")
	}

	if params.Password == "" {
		return nil, fmt.Errorf("No password parameter provided")
	}

	if params.AuthURL == "" {
		return nil, fmt.Errorf("No authurl parameter provided")
	}

	if params.Container == "" {
		return nil, fmt.Errorf("No container parameter provided")
	}

	if params.ChunkSize < minChunkSize {
		return nil, fmt.Errorf("The chunksize %#v parameter should be a number that is larger than or equal to %d", params.ChunkSize, minChunkSize)
	}

	params.LargeObjectType = strings.ToUpper(params.LargeObjectType)
	if params.LargeObjectType != "" &&
		params.LargeObjectType != largeObjectTypeDLO &&
		params.LargeObjectType != largeObjectTypeSLO {
		return nil, fmt.Errorf("LargeObjectType must be either empty (automatic), %s or %s, got: %q.", largeObjectTypeDLO, largeObjectTypeSLO, params.LargeObjectType)
	}

	return New(params)
}

// New constructs a new Driver with the given Openstack Swift credentials and container name
func New(params Parameters) (*Driver, error) {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: 2048,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: params.InsecureSkipVerify},
	}

	ct := &swift.Connection{
		UserName:       params.Username,
		ApiKey:         params.Password,
		AuthUrl:        params.AuthURL,
		Region:         params.Region,
		AuthVersion:    params.AuthVersion,
		UserAgent:      "distribution/" + version.Version,
		Tenant:         params.Tenant,
		TenantId:       params.TenantID,
		Domain:         params.Domain,
		DomainId:       params.DomainID,
		TenantDomain:   params.TenantDomain,
		TenantDomainId: params.TenantDomainID,
		TrustId:        params.TrustID,
		EndpointType:   swift.EndpointType(params.EndpointType),
		Transport:      transport,
		ConnectTimeout: 60 * time.Second,
		Timeout:        15 * 60 * time.Second,
	}
	err := ct.Authenticate()
	if err != nil {
		return nil, fmt.Errorf("Swift authentication failed: %s", err)
	}

	if _, _, err := ct.Container(params.Container); err == swift.ContainerNotFound {
		if err = ct.ContainerCreate(params.Container, nil); err != nil {
			return nil, fmt.Errorf("Failed to create container %s (%s)", params.Container, err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("Failed to retrieve info about container %s (%s)", params.Container, err)
	}

	d := &driver{
		Conn:            ct,
		Container:       params.Container,
		Prefix:          params.Prefix,
		ChunkSize:       params.ChunkSize,
		TempURLMethods:  make([]string, 0),
		AccessKey:       params.AccessKey,
		LargeObjectType: params.LargeObjectType,
	}

	info := swiftInfo{}
	if config, err := d.Conn.QueryInfo(); err == nil {
		_, d.BulkDeleteSupport = config["bulk_delete"]

		if err := mapstructure.Decode(config, &info); err == nil {
			d.TempURLContainerKey = info.Swift.Version >= "2.3.0"
			d.TempURLMethods = info.Tempurl.Methods
			if d.BulkDeleteSupport {
				d.BulkDeleteMaxDeletes = info.BulkDelete.MaxDeletesPerRequest
			}
		}

		if d.LargeObjectType == "" {
			if config.SupportsSLO() {
				d.LargeObjectType = largeObjectTypeSLO
			} else {
				d.LargeObjectType = largeObjectTypeDLO
			}
		}
	} else {
		d.TempURLContainerKey = params.TempURLContainerKey
		d.TempURLMethods = params.TempURLMethods
	}

	if len(d.TempURLMethods) > 0 {
		secretKey := params.SecretKey
		if secretKey == "" {
			secretKey, _ = generateSecret()
		}

		// Since Swift 2.2.2, we can now set secret keys on containers
		// in addition to the account secret keys. Use them in preference.
		if d.TempURLContainerKey {
			_, containerHeaders, err := d.Conn.Container(d.Container)
			if err != nil {
				return nil, fmt.Errorf("Failed to fetch container info %s (%s)", d.Container, err)
			}

			d.SecretKey = containerHeaders["X-Container-Meta-Temp-Url-Key"]
			if d.SecretKey == "" || (params.SecretKey != "" && d.SecretKey != params.SecretKey) {
				m := swift.Metadata{}
				m["temp-url-key"] = secretKey
				if d.Conn.ContainerUpdate(d.Container, m.ContainerHeaders()); err == nil {
					d.SecretKey = secretKey
				}
			}
		} else {
			// Use the account secret key
			_, accountHeaders, err := d.Conn.Account()
			if err != nil {
				return nil, fmt.Errorf("Failed to fetch account info (%s)", err)
			}

			d.SecretKey = accountHeaders["X-Account-Meta-Temp-Url-Key"]
			if d.SecretKey == "" || (params.SecretKey != "" && d.SecretKey != params.SecretKey) {
				m := swift.Metadata{}
				m["temp-url-key"] = secretKey
				if err := d.Conn.AccountUpdate(m.AccountHeaders()); err == nil {
					d.SecretKey = secretKey
				}
			}
		}
	}

	return &Driver{
		baseEmbed: baseEmbed{
			Base: base.Base{
				StorageDriver: d,
			},
		},
	}, nil
}

// Implement the storagedriver.StorageDriver interface

func (d *driver) Name() string {
	return driverName
}

// GetContent retrieves the content stored at "path" as a []byte.
func (d *driver) GetContent(ctx context.Context, path string) ([]byte, error) {
	content, err := d.Conn.ObjectGetBytes(d.Container, d.swiftPath(path))
	if err == swift.ObjectNotFound {
		return nil, storagedriver.PathNotFoundError{Path: path}
	}
	return content, err
}

// PutContent stores the []byte content at a location designated by "path".
func (d *driver) PutContent(ctx context.Context, path string, contents []byte) error {
	err := d.Conn.ObjectPutBytes(d.Container, d.swiftPath(path), contents, contentType)
	if err == swift.ObjectNotFound {
		return storagedriver.PathNotFoundError{Path: path}
	}
	return err
}

// Reader retrieves an io.ReadCloser for the content stored at "path" with a
// given byte offset.
func (d *driver) Reader(ctx context.Context, path string, offset int64) (file io.ReadCloser, err error) {
	headers := make(swift.Headers)
	headers["Range"] = "bytes=" + strconv.FormatInt(offset, 10) + "-"

	for {
		file, headers, err = d.Conn.ObjectOpen(d.Container, d.swiftPath(path), false, headers)
		if err != nil {
			if err == swift.ObjectNotFound {
				return nil, storagedriver.PathNotFoundError{Path: path}
			}
			if swiftErr, ok := err.(*swift.Error); ok && swiftErr.StatusCode == http.StatusRequestedRangeNotSatisfiable {
				return ioutil.NopCloser(bytes.NewReader(nil)), nil
			}
			return file, err
		}
		return file, nil
	}
}

// Writer returns a FileWriter which will store the content written to it
// at the location designated by "path" after the call to Commit.
func (d *driver) Writer(ctx context.Context, path string, append bool) (storagedriver.FileWriter, error) {
	segmentsPath, err := d.swiftSegmentPath(path)
	if err != nil {
		return nil, err
	}
	flags := 0
	if append {
		flags |= os.O_APPEND
	}
	opts := swift.LargeObjectOpts{
		Container:        d.Container,
		SegmentContainer: d.Container,
		ObjectName:       d.swiftPath(path),
		CheckHash:        true,
		ContentType:      contentType,
		ChunkSize:        int64(d.ChunkSize),
		SegmentPrefix:    segmentsPath,
		Flags:            flags,
	}

	var out swift.LargeObjectFile
	if d.LargeObjectType == largeObjectTypeSLO {
		out, err = d.Conn.StaticLargeObjectCreateFile(&opts)
	} else {
		out, err = d.Conn.DynamicLargeObjectCreateFile(&opts)
	}
	if err != nil {
		return nil, err
	}
	return d.newWriter(path, out), nil
}

// Stat retrieves the FileInfo for the given path, including the current size
// in bytes and the creation time.
func (d *driver) Stat(ctx context.Context, path string) (storagedriver.FileInfo, error) {
	swiftPath := d.swiftPath(path)
	opts := &swift.ObjectsOpts{
		Prefix:    swiftPath,
		Delimiter: '/',
	}

	objects, err := d.Conn.ObjectsAll(d.Container, opts)
	if err != nil {
		if err == swift.ContainerNotFound {
			return nil, storagedriver.PathNotFoundError{Path: path}
		}
		return nil, err
	}

	fi := storagedriver.FileInfoFields{
		Path: strings.TrimPrefix(strings.TrimSuffix(swiftPath, "/"), d.swiftPath("/")),
	}

	for _, obj := range objects {
		if obj.PseudoDirectory && obj.Name == swiftPath+"/" {
			fi.IsDir = true
			return storagedriver.FileInfoInternal{FileInfoFields: fi}, nil
		} else if obj.Name == swiftPath {
			// The file exists. But on Swift 1.12, the 'bytes' field is always 0 so
			// we need to do a separate HEAD request.
			break
		}
	}

	info, _, err := d.Conn.Object(d.Container, swiftPath)
	if err != nil {
		if err == swift.ObjectNotFound {
			return nil, storagedriver.PathNotFoundError{Path: path}
		}
		return nil, err
	}

	fi.IsDir = false
	fi.Size = info.Bytes
	fi.ModTime = info.LastModified
	return storagedriver.FileInfoInternal{FileInfoFields: fi}, nil
}

// List returns a list of the objects that are direct descendants of the given path.
func (d *driver) List(ctx context.Context, path string) ([]string, error) {
	var files []string

	prefix := d.swiftPath(path)
	if prefix != "" {
		prefix += "/"
	}

	opts := &swift.ObjectsOpts{
		Prefix:    prefix,
		Delimiter: '/',
	}

	objects, err := d.Conn.ObjectsAll(d.Container, opts)
	for _, obj := range objects {
		files = append(files, strings.TrimPrefix(strings.TrimSuffix(obj.Name, "/"), d.swiftPath("/")))
	}

	if err == swift.ContainerNotFound || (len(objects) == 0 && path != "/") {
		return files, storagedriver.PathNotFoundError{Path: path}
	}
	return files, err
}

// Move moves an object stored at sourcePath to destPath, removing the original
// object.
func (d *driver) Move(ctx context.Context, sourcePath string, destPath string) error {
	_, headers, err := d.Conn.Object(d.Container, d.swiftPath(sourcePath))
	if err == nil {
		if headers.IsLargeObjectDLO() {
			err = d.Conn.DynamicLargeObjectMove(d.Container, d.swiftPath(sourcePath), d.Container, d.swiftPath(destPath))
		} else if headers.IsLargeObjectSLO() {
			err = d.Conn.StaticLargeObjectMove(d.Container, d.swiftPath(sourcePath), d.Container, d.swiftPath(destPath))
		} else {
			err = d.Conn.ObjectMove(d.Container, d.swiftPath(sourcePath), d.Container, d.swiftPath(destPath))
		}
	}
	if err == swift.ObjectNotFound {
		return storagedriver.PathNotFoundError{Path: sourcePath}
	}
	if err != nil {
		return err
	}
	return d.waitObjectDelete(sourcePath)
}

// Delete recursively deletes all objects stored at "path" and its subpaths.
func (d *driver) Delete(ctx context.Context, path string) error {
	opts := swift.ObjectsOpts{
		Prefix: d.swiftPath(path) + "/",
	}

	objects, err := d.Conn.ObjectsAll(d.Container, &opts)
	if err != nil {
		if err == swift.ContainerNotFound {
			return storagedriver.PathNotFoundError{Path: path}
		}
		return err
	}

	var headers swift.Headers
	var largeObjects []swift.Object
	for i := 0; i < len(objects); i++ {
		obj := objects[i]
		if obj.PseudoDirectory {
			continue
		}
		if _, headers, err = d.Conn.Object(d.Container, obj.Name); err == nil {
			if headers.IsLargeObject() {
				largeObjects = append(largeObjects, obj)
				objects = append(objects[:i], objects[i+1:]...)
				i--
			}
		} else {
			if err == swift.ObjectNotFound {
				return storagedriver.PathNotFoundError{Path: obj.Name}
			}
			return err
		}
	}

	if d.BulkDeleteSupport && len(objects) > 0 && d.BulkDeleteMaxDeletes > 0 {
		filenames := make([]string, len(objects))
		for i, obj := range objects {
			filenames[i] = obj.Name
		}

		chunks, err := chunkFilenames(filenames, d.BulkDeleteMaxDeletes)
		if err != nil {
			return err
		}
		for _, chunk := range chunks {
			_, err := d.Conn.BulkDelete(d.Container, chunk)
			// Don't fail on ObjectNotFound because eventual consistency
			// makes this situation normal.
			if err != nil && err != swift.Forbidden && err != swift.ObjectNotFound {
				if err == swift.ContainerNotFound {
					return storagedriver.PathNotFoundError{Path: path}
				}
				return err
			}
		}
	} else {
		for _, obj := range objects {
			if err = d.Conn.ObjectDelete(d.Container, obj.Name); err != nil {
				if err == swift.ObjectNotFound {
					return storagedriver.PathNotFoundError{Path: obj.Name}
				}
				return err
			}
		}
	}

	for _, obj := range largeObjects {
		if err = d.Conn.LargeObjectDelete(d.Container, obj.Name); err != nil {
			if err == swift.ObjectNotFound {
				return storagedriver.PathNotFoundError{Path: obj.Name}
			}
			return err
		}
	}

	_, headers, err = d.Conn.Object(d.Container, d.swiftPath(path))
	if err == nil {
		if headers.IsLargeObject() {
			err = d.Conn.LargeObjectDelete(d.Container, d.swiftPath(path))
		} else {
			err = d.Conn.ObjectDelete(d.Container, d.swiftPath(path))
		}
		if err != nil {
			if err == swift.ObjectNotFound {
				return storagedriver.PathNotFoundError{Path: path}
			}
			return err
		}
	} else if err == swift.ObjectNotFound {
		if len(objects) == 0 && len(largeObjects) == 0 {
			return storagedriver.PathNotFoundError{Path: path}
		}
	} else {
		return err
	}
	return nil
}

// URLFor returns a URL which may be used to retrieve the content stored at the given path.
func (d *driver) URLFor(ctx context.Context, path string, options map[string]interface{}) (string, error) {
	if d.SecretKey == "" {
		return "", storagedriver.ErrUnsupportedMethod{}
	}

	methodString := "GET"
	method, ok := options["method"]
	if ok {
		if methodString, ok = method.(string); !ok {
			return "", storagedriver.ErrUnsupportedMethod{}
		}
	}

	if methodString == "HEAD" {
		// A "HEAD" request on a temporary URL is allowed if the
		// signature was generated with "GET", "POST" or "PUT"
		methodString = "GET"
	}

	supported := false
	for _, method := range d.TempURLMethods {
		if method == methodString {
			supported = true
			break
		}
	}

	if !supported {
		return "", storagedriver.ErrUnsupportedMethod{}
	}

	expiresTime := time.Now().Add(20 * time.Minute)
	expires, ok := options["expiry"]
	if ok {
		et, ok := expires.(time.Time)
		if ok {
			expiresTime = et
		}
	}

	tempURL := d.Conn.ObjectTempUrl(d.Container, d.swiftPath(path), d.SecretKey, methodString, expiresTime)

	if d.AccessKey != "" {
		// On HP Cloud, the signature must be in the form of tenant_id:access_key:signature
		url, _ := url.Parse(tempURL)
		query := url.Query()
		query.Set("temp_url_sig", fmt.Sprintf("%s:%s:%s", d.Conn.TenantId, d.AccessKey, query.Get("temp_url_sig")))
		url.RawQuery = query.Encode()
		tempURL = url.String()
	}

	return tempURL, nil
}

func (d *driver) swiftPath(path string) string {
	return strings.TrimLeft(strings.TrimRight(d.Prefix+"/files"+path, "/"), "/")
}

func (d *driver) swiftSegmentPath(path string) (string, error) {
	checksum := sha1.New()
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	path = hex.EncodeToString(checksum.Sum(append([]byte(path), random...)))
	return strings.TrimLeft(strings.TrimRight(d.Prefix+"/segments/"+path[0:3]+"/"+path[3:], "/"), "/"), nil
}

func (d *driver) waitObjectDelete(path string) error {
	var err error
	timeout := time.After(waitAfterMoveTimeout)
	for {
		_, _, err = d.Conn.Object(d.Container, d.swiftPath(path))
		if err != nil {
			break
		}
		select {
		case <-time.After(waitAfterMoveWait):
		case <-timeout:
			return fmt.Errorf("Timeout expired while waiting for object %s to disappear", path)
		}
	}
	if err == swift.ObjectNotFound {
		return nil
	}
	return err
}

func chunkFilenames(slice []string, maxSize int) (chunks [][]string, err error) {
	if maxSize > 0 {
		for offset := 0; offset < len(slice); offset += maxSize {
			chunkSize := maxSize
			if offset+chunkSize > len(slice) {
				chunkSize = len(slice) - offset
			}
			chunks = append(chunks, slice[offset:offset+chunkSize])
		}
	} else {
		return nil, fmt.Errorf("Max chunk size must be > 0")
	}
	return
}

func generateSecret() (string, error) {
	var secretBytes [32]byte
	if _, err := rand.Read(secretBytes[:]); err != nil {
		return "", fmt.Errorf("could not generate random bytes for Swift secret key: %v", err)
	}
	return hex.EncodeToString(secretBytes[:]), nil
}

type writer struct {
	driver    *driver
	writer    swift.LargeObjectFile
	path      string
	closed    bool
	committed bool
	cancelled bool
}

func (d *driver) newWriter(path string, loWriter swift.LargeObjectFile) storagedriver.FileWriter {
	return &writer{
		driver: d,
		writer: loWriter,
		path:   path,
	}
}

func (w *writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, fmt.Errorf("already closed")
	} else if w.committed {
		return 0, fmt.Errorf("already committed")
	} else if w.cancelled {
		return 0, fmt.Errorf("already cancelled")
	}

	return w.writer.Write(p)
}

func (w *writer) Size() int64 {
	return w.writer.Size()
}

func (w *writer) Close() error {
	if w.closed {
		return fmt.Errorf("already closed")
	}

	if err := w.writer.Close(); err != nil {
		return err
	}
	w.closed = true

	return nil
}

func (w *writer) Cancel() error {
	if w.closed {
		return fmt.Errorf("already closed")
	} else if w.committed {
		return fmt.Errorf("already committed")
	}
	w.cancelled = true
	return w.driver.Delete(context.Background(), w.path)
}

func (w *writer) Commit() error {
	if w.closed {
		return fmt.Errorf("already closed")
	} else if w.committed {
		return fmt.Errorf("already committed")
	} else if w.cancelled {
		return fmt.Errorf("already cancelled")
	}

	if err := w.writer.Flush(); err != nil {
		return err
	}
	w.committed = true

	return nil
}
