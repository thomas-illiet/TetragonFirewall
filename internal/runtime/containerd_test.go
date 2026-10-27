package runtime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeTasks struct {
	pid uint32
	err error
}

func (f fakeTasks) TaskPID(context.Context, string) (uint32, error) { return f.pid, f.err }

func TestReadUnifiedCgroup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(path, []byte("0::/kubepods.slice/pod.scope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readUnifiedCgroup(path)
	if err != nil || got != "/kubepods.slice/pod.scope" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestCgroupPath(t *testing.T) {
	root := t.TempDir()
	hostProc := filepath.Join(root, "proc")
	cgroupRoot := filepath.Join(root, "cgroup")
	if err := os.MkdirAll(filepath.Join(hostProc, "42"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(cgroupRoot, "kubepods", "container"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostProc, "42", "cgroup"), []byte("0::/kubepods/container\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := &Containerd{tasks: fakeTasks{pid: 42}, hostProc: hostProc, cgroup: cgroupRoot}
	got, err := runtime.CgroupPath(context.Background(), "long-container-id")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(cgroupRoot, "kubepods", "container")
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCgroupPathErrors(t *testing.T) {
	t.Run("task", func(t *testing.T) {
		runtime := &Containerd{tasks: fakeTasks{err: errors.New("missing task")}}
		if _, err := runtime.CgroupPath(context.Background(), "id"); err == nil {
			t.Fatal("expected task error")
		}
	})
	t.Run("proc", func(t *testing.T) {
		runtime := &Containerd{tasks: fakeTasks{pid: 42}, hostProc: t.TempDir(), cgroup: t.TempDir()}
		if _, err := runtime.CgroupPath(context.Background(), "id"); err == nil {
			t.Fatal("expected proc error")
		}
	})
	t.Run("not-directory", func(t *testing.T) {
		root := t.TempDir()
		hostProc := filepath.Join(root, "proc")
		if err := os.MkdirAll(filepath.Join(hostProc, "42"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(hostProc, "42", "cgroup"), []byte("0::/target\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cgroupRoot := filepath.Join(root, "cgroup")
		if err := os.MkdirAll(cgroupRoot, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cgroupRoot, "target"), []byte("file"), 0o600); err != nil {
			t.Fatal(err)
		}
		runtime := &Containerd{tasks: fakeTasks{pid: 42}, hostProc: hostProc, cgroup: cgroupRoot}
		if _, err := runtime.CgroupPath(context.Background(), "id"); err == nil {
			t.Fatal("expected non-directory error")
		}
	})
}

func TestReadUnifiedCgroupErrors(t *testing.T) {
	if _, err := readUnifiedCgroup(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected open error")
	}
	path := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(path, []byte("1:name:/legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readUnifiedCgroup(path); err == nil {
		t.Fatal("expected unified hierarchy error")
	}
}

func TestHelpers(t *testing.T) {
	if got := shortID("1234567890123456"); got != "123456789012" {
		t.Fatalf("shortID=%q", got)
	}
	if got := shortID("short"); got != "short" {
		t.Fatalf("shortID=%q", got)
	}
	if err := (&Containerd{}).Close(); err != nil {
		t.Fatal(err)
	}
}
