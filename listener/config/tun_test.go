package config

import (
	"reflect"
	"testing"
)

// TestTunEqualComparesEveryField changes one field at a time and expects
// Equal to notice, so a field added to Tun but not to Equal (which would keep
// a reload from applying it) fails here.
func TestTunEqualComparesEveryField(t *testing.T) {
	typ := reflect.TypeOf(Tun{})
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		t.Run(field.Name, func(t *testing.T) {
			var base, changed Tun
			v := reflect.ValueOf(&changed).Elem().Field(i)
			switch v.Kind() {
			case reflect.Bool:
				v.SetBool(true)
			case reflect.String:
				v.SetString("x")
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				v.SetInt(1)
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				v.SetUint(1)
			case reflect.Slice:
				v.Set(reflect.MakeSlice(v.Type(), 1, 1))
			default:
				t.Fatalf("no test value for %s of kind %s", field.Name, v.Kind())
			}
			if base.Equal(changed) {
				t.Fatalf("Equal ignores %s", field.Name)
			}
			if !changed.Equal(changed) {
				t.Fatalf("Equal is not reflexive for %s", field.Name)
			}
		})
	}
}
