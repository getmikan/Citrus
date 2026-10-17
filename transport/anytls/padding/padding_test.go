package padding

import "testing"

func TestNewPaddingFactoryRejectsBadStop(t *testing.T) {
	for _, stop := range []string{"-1", "4294967296", "x", ""} {
		if p := NewPaddingFactory([]byte("stop=" + stop + "\n0=30-30")); p != nil {
			t.Errorf("stop=%q: got a factory with Stop=%d, want nil", stop, p.Stop)
		}
	}
	p := NewPaddingFactory([]byte("stop=4294967295\n0=30-30"))
	if p == nil || p.Stop != 4294967295 {
		t.Fatalf("stop=4294967295: got %v", p)
	}
}

func TestGenerateRecordPayloadSizesBounds(t *testing.T) {
	p := NewPaddingFactory([]byte("stop=2\n0=100-200,c,1000000000-1000000001,70000-70000,0-10,65535-65535\n1=-5-10"))
	if p == nil {
		t.Fatal("factory is nil")
	}
	sizes := p.GenerateRecordPayloadSizes(0)
	if len(sizes) != 3 {
		t.Fatalf("sizes = %v, want 3 entries", sizes)
	}
	if sizes[0] < 100 || sizes[0] > 200 {
		t.Errorf("sizes[0] = %d, want 100..200", sizes[0])
	}
	if sizes[1] != CheckMark {
		t.Errorf("sizes[1] = %d, want CheckMark", sizes[1])
	}
	if sizes[2] != 65535 {
		t.Errorf("sizes[2] = %d, want 65535", sizes[2])
	}
	if sizes := p.GenerateRecordPayloadSizes(1); len(sizes) != 0 {
		t.Errorf("negative range: sizes = %v, want none", sizes)
	}
}

func TestDefaultPaddingScheme(t *testing.T) {
	p := NewPaddingFactory(DefaultPaddingScheme)
	if p == nil || p.Stop != 8 {
		t.Fatalf("default scheme: got %v", p)
	}
	if sizes := p.GenerateRecordPayloadSizes(2); len(sizes) != 9 {
		t.Errorf("pkt 2: sizes = %v, want 9 entries", sizes)
	}
}
