package opensearch

import (
	"errors"
	"fmt"
)

var (
	ErrSecretKeyNotFound        = errors.New("secret key not found")
	ErrPasswordSecretNotFound   = errors.New("password secret not found")
	ErrClusterSettingsOperation = errors.New("cluster settings failed")
	ErrClusterStatusOperation   = errors.New("cluster status failed")
)

func ErrSecretKeyNotExist(key string, name string) error {
	return fmt.Errorf("key does not exist %w: %s in %s", ErrSecretKeyNotFound, key, name)
}

func ErrClusterSettingsPutFailed(resp string) error {
	return fmt.Errorf("put error %w: %s", ErrClusterSettingsOperation, resp)
}

func ErrClusterSettingsGetFailed(resp string) error {
	return fmt.Errorf("get error %w: %s", ErrClusterSettingsOperation, resp)
}

func ErrClusterStatusGetFailed(resp string) error {
	return fmt.Errorf("get error %w: %s", ErrClusterStatusOperation, resp)
}
