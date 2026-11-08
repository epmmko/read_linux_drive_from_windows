#!/usr/bin/env python3
"""
extfs_gui.py - read-only "File Explorer" for Linux (ext2/3/4) disks, on Windows.

    python extfs_gui.py                 (it offers to restart itself as Administrator)
    python extfs_gui.py disk.img        (open a disk image file instead)

Needs only Python (with Tkinter, which the python.org installer includes) and
extfs_backend.py in the same folder. Nothing is ever written to the Linux disk.

Pick a disk and a partition, press Open, browse like Explorer, select files or
folders (Ctrl/Shift-click) and press "Copy to..." - or double-click a file to
open it. Double-click a folder / use the tree on the left to navigate.
"""
import os
import posixpath
import queue
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import extfs_backend as eb  # noqa: E402

APP_TITLE = "Ext4 Explorer - read-only"


# ----------------------------------------------------------------------------- helpers
def fmt_time(ts):
    try:
        return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return ""


def type_text(e):
    if e.kind == "dir":
        return "File folder"
    if e.kind == "symlink":
        return "Symbolic link"
    if e.kind == "file":
        ext = os.path.splitext(e.name)[1].lstrip(".")
        return ("%s File" % ext.upper()) if ext else "File"
    return "Special file"


def size_text(e):
    return eb.human_size(e.size) if e.kind in ("file", "symlink") else ""


def relaunch_as_admin():
    import ctypes
    params = subprocess.list2cmdline([os.path.abspath(__file__)] + sys.argv[1:])
    return ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, os.getcwd(), 1) > 32


def open_with_os(path):
    if os.name == "nt":
        os.startfile(path)  # noqa: S606
    else:
        subprocess.Popen(["xdg-open", path])


def make_icons(master):
    def new():
        return tk.PhotoImage(master=master, width=16, height=16)

    folder = new()
    folder.put("#C99A1B", to=(1, 3, 7, 5))
    folder.put("#C99A1B", to=(1, 5, 15, 14))
    folder.put("#F4CB55", to=(2, 6, 14, 13))

    def page(img):
        img.put("#707070", to=(3, 1, 13, 15))
        img.put("#FFFFFF", to=(4, 2, 12, 14))

    file_ = new()
    page(file_)
    for y in (4, 6, 8, 10):
        file_.put("#9AA5B1", to=(5, y, 11, y + 1))
    link = new()
    page(link)
    link.put("#2B7DE9", to=(5, 8, 11, 10))
    link.put("#2B7DE9", to=(9, 6, 11, 12))
    other = new()
    page(other)
    other.put("#B04A4A", to=(6, 6, 10, 10))
    return {"folder": folder, "file": file_, "symlink": link, "other": other}


# ----------------------------------------------------------------------------- copy dialog
class CopyDialog(tk.Toplevel):
    """Modal progress window; runs estimate + extract in a worker thread."""

    def __init__(self, app, sources, dest, title, after):
        super().__init__(app)
        self.app, self.sources, self.dest, self.after_cb = app, sources, dest, after
        self.title(title)
        self.resizable(False, False)
        self.transient(app)
        self.prog = eb.Progress()
        self.result = None
        self.error = None
        self.finished = False
        self.t0 = time.time()
        self._determinate = False
        f = ttk.Frame(self, padding=14)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="To: " + dest, wraplength=560).pack(anchor="w")
        self.lbl_cur = ttk.Label(f, text="Calculating size...", wraplength=560, width=80)
        self.lbl_cur.pack(anchor="w", pady=(8, 4))
        self.pbar = ttk.Progressbar(f, length=560, mode="indeterminate")
        self.pbar.pack(fill="x")
        self.pbar.start(12)
        self.lbl_stats = ttk.Label(f, text="")
        self.lbl_stats.pack(anchor="w", pady=(6, 10))
        self.btn = ttk.Button(f, text="Cancel", command=self._cancel)
        self.btn.pack(anchor="e")
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        try:
            self.wait_visibility()
            self.grab_set()
        except tk.TclError:
            pass
        threading.Thread(target=self._work, daemon=True).start()
        self.after(100, self._tick)

    def _work(self):
        p = self.prog
        try:
            p.phase = "scanning"
            files, total = eb.estimate(self.app.fs, self.sources, progress=p)
            p.files_total, p.bytes_total = files, total
            if p.cancel.is_set():
                self.result = eb.ExtractResult(cancelled=True)
                return
            probe = os.path.abspath(self.dest)
            while probe and not os.path.exists(probe):
                parent = os.path.dirname(probe)
                if parent == probe:
                    break
                probe = parent
            free = shutil.disk_usage(probe).free
            if total > free:
                raise OSError("Not enough free space on the destination: %s needed, %s free."
                              % (eb.human_size(total), eb.human_size(free)))
            self.result = eb.extract(self.app.fs, self.sources, self.dest, progress=p)
        except BaseException as e:  # shown to the user
            self.error = e
        finally:
            self.finished = True

    def _cancel(self):
        self.prog.cancel.set()
        self.btn.config(state="disabled")
        self.lbl_cur.config(text="Cancelling...")

    def _tick(self):
        p = self.prog
        if self.finished:
            try:
                self.grab_release()
            except tk.TclError:
                pass
            self.destroy()
            self.after_cb(self.dest, self.result, self.error)
            return
        if p.phase == "copying" and p.bytes_total >= 0:
            if not self._determinate:
                self.pbar.stop()
                self.pbar.config(mode="determinate", maximum=max(1, p.bytes_total), value=0)
                self._determinate = True
            self.pbar.config(value=p.bytes_done)
            el = max(0.001, time.time() - self.t0)
            self.lbl_cur.config(text=p.current[-110:] if p.current else "")
            self.lbl_stats.config(text="%d of %d files   %s of %s   %.1f MB/s   %d error(s)" % (
                p.files_done, p.files_total, eb.human_size(p.bytes_done), eb.human_size(p.bytes_total),
                p.bytes_done / el / 1e6, p.errors))
        self.after(100, self._tick)


# ----------------------------------------------------------------------------- main window
class App(tk.Tk):
    def __init__(self, image=None):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1150x700")
        self.minsize(820, 460)
        self.fs = None
        self.cwd = "/"
        self.hist, self.hpos = [], -1
        self.cur_entries, self.entries = [], []
        self.sort_col, self.sort_rev = "name", False
        self.q = queue.Queue()
        self.disks, self.parts = [], []
        self.scan_target = None
        self.node_path = {}
        self.tree_root = None
        self.tmp_dirs = []
        self.show_hidden = tk.BooleanVar(value=True)
        self.addr_var = tk.StringVar(value="/")
        style = ttk.Style(self)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Treeview", rowheight=22)
        self.icons = make_icons(self)
        self._build_menu()
        self._build_toolbar()
        self._build_body()
        self._build_status()
        self._bind_keys()
        self.protocol("WM_DELETE_WINDOW", self._quit)
        self.after(60, self._pump)
        self.after(250, lambda: self._startup(image))

    # ---- plumbing ---------------------------------------------------------------------
    def _pump(self):
        try:
            while True:
                self.q.get_nowait()()
        except queue.Empty:
            pass
        except Exception as e:  # never let a UI callback kill the loop
            self._error("Unexpected error", e)
        self.after(60, self._pump)

    def _bg(self, work, done):
        def run():
            try:
                r, e = work(), None
            except BaseException as ex:
                r, e = None, ex
            self.q.put(lambda: done(r, e))
        threading.Thread(target=run, daemon=True).start()

    def _error(self, title, exc):
        text = "%s: %s" % (type(exc).__name__, exc)
        if isinstance(exc, PermissionError):
            text += "\n\nReading a physical disk needs Administrator rights. Start this program from an Administrator terminal."
        messagebox.showerror(title, text, parent=self)

    def _set_status(self, text):
        self.status.config(text=text)

    # ---- construction -----------------------------------------------------------------
    def _build_menu(self):
        m = tk.Menu(self)
        fm = tk.Menu(m, tearoff=0)
        fm.add_command(label="Open disk image...", accelerator="Ctrl+O", command=self.open_image_dialog)
        fm.add_command(label="Rescan disks", command=self.rescan_disks)
        fm.add_separator()
        fm.add_command(label="Exit", command=self._quit)
        m.add_cascade(label="File", menu=fm)
        em = tk.Menu(m, tearoff=0)
        em.add_command(label="Copy selected to...", command=self.copy_selected)
        em.add_command(label="Select all", accelerator="Ctrl+A", command=self._select_all)
        em.add_command(label="Copy path", command=self._copy_path)
        m.add_cascade(label="Edit", menu=em)
        vm = tk.Menu(m, tearoff=0)
        vm.add_command(label="Refresh", accelerator="F5", command=self.refresh)
        vm.add_checkbutton(label="Show hidden (dot) files", variable=self.show_hidden, command=self._hidden_toggled)
        m.add_cascade(label="View", menu=vm)
        hm = tk.Menu(m, tearoff=0)
        hm.add_command(label="About / limits", command=self._about)
        m.add_cascade(label="Help", menu=hm)
        self.config(menu=m)

    def _build_toolbar(self):
        top = ttk.Frame(self, padding=(8, 6, 8, 2))
        top.pack(fill="x")
        ttk.Label(top, text="Disk:").pack(side="left")
        self.disk_cb = ttk.Combobox(top, state="readonly", width=44)
        self.disk_cb.pack(side="left", padx=(4, 10))
        self.disk_cb.bind("<<ComboboxSelected>>", self._disk_selected)
        ttk.Label(top, text="Partition:").pack(side="left")
        self.part_cb = ttk.Combobox(top, state="readonly", width=44)
        self.part_cb.pack(side="left", padx=(4, 6))
        ttk.Button(top, text="Open", command=self._open_selected_partition).pack(side="left")
        nav = ttk.Frame(self, padding=(8, 2, 8, 6))
        nav.pack(fill="x")
        self.btn_back = ttk.Button(nav, text="◀", width=3, command=self.back)
        self.btn_fwd = ttk.Button(nav, text="▶", width=3, command=self.fwd)
        self.btn_up = ttk.Button(nav, text="▲", width=3, command=self.up)
        for b in (self.btn_back, self.btn_fwd, self.btn_up):
            b.pack(side="left", padx=(0, 2))
        addr = ttk.Entry(nav, textvariable=self.addr_var)
        addr.pack(side="left", fill="x", expand=True, padx=6)
        addr.bind("<Return>", lambda e: self.goto(self.addr_var.get()))
        ttk.Button(nav, text="Refresh", command=self.refresh).pack(side="left", padx=(0, 6))
        ttk.Button(nav, text="Copy to...", command=self.copy_selected).pack(side="left")
        self._nav_state()

    def _build_body(self):
        pw = ttk.PanedWindow(self, orient="horizontal")
        pw.pack(fill="both", expand=True, padx=8)
        left = ttk.Frame(pw)
        self.tree = ttk.Treeview(left, show="tree", selectmode="browse")
        sb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="left", fill="y")
        self.tree.bind("<<TreeviewOpen>>", self._on_tree_open)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        pw.add(left, weight=1)
        right = ttk.Frame(pw)
        self.lst = ttk.Treeview(right, columns=("modified", "type", "size"), selectmode="extended")
        ys = ttk.Scrollbar(right, orient="vertical", command=self.lst.yview)
        xs = ttk.Scrollbar(right, orient="horizontal", command=self.lst.xview)
        self.lst.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.lst.column("#0", width=380, stretch=True)
        self.lst.column("modified", width=140, stretch=False)
        self.lst.column("type", width=120, stretch=False)
        self.lst.column("size", width=90, stretch=False, anchor="e")
        self._headings()
        self.lst.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)
        self.lst.bind("<Double-1>", self._on_double)
        self.lst.bind("<Return>", lambda e: self._open_item_selected())
        self.lst.bind("<<TreeviewSelect>>", lambda e: self._update_status())
        self.lst.bind("<Button-3>", self._context)
        pw.add(right, weight=4)
        self.menu = tk.Menu(self, tearoff=0)
        self.menu.add_command(label="Open", command=self._open_item_selected)
        self.menu.add_command(label="Copy to...", command=self.copy_selected)
        self.menu.add_command(label="Copy path", command=self._copy_path)
        self.menu.add_separator()
        self.menu.add_command(label="Properties", command=self._properties)

    def _build_status(self):
        bar = ttk.Frame(self, padding=(8, 3))
        bar.pack(fill="x")
        self.status = ttk.Label(bar, text="Starting...")
        self.status.pack(side="left")
        self.fs_label = ttk.Label(bar, text="")
        self.fs_label.pack(side="right")

    def _bind_keys(self):
        self.bind("<F5>", lambda e: self.refresh())
        self.bind("<BackSpace>", lambda e: self.up() if self.focus_get() is not None and "entry" not in str(self.focus_get()).lower() else None)
        self.bind("<Alt-Left>", lambda e: self.back())
        self.bind("<Alt-Right>", lambda e: self.fwd())
        self.bind("<Control-o>", lambda e: self.open_image_dialog())
        self.lst.bind("<Control-a>", lambda e: (self._select_all(), "break")[1])

    def _headings(self):
        names = {"#0": ("Name", "name"), "modified": ("Date modified", "modified"),
                 "type": ("Type", "type"), "size": ("Size", "size")}
        for col, (label, key) in names.items():
            arrow = (" ▼" if self.sort_rev else " ▲") if key == self.sort_col else ""
            self.lst.heading(col, text=label + arrow, command=lambda k=key: self._sort(k))

    # ---- disks & partitions -------------------------------------------------------------
    def _startup(self, image):
        if os.name == "nt":
            try:
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
        if image:
            self._scan_image(image)
            return
        if os.name == "nt" and not eb.is_admin():
            if messagebox.askyesno("Administrator needed",
                                   "Reading a physical disk needs Administrator rights.\n\n"
                                   "Restart this program as Administrator now?\n"
                                   "(Choose No to only open disk image files.)", parent=self):
                try:
                    if relaunch_as_admin():
                        self.destroy()
                        return
                except Exception as e:
                    self._error("Could not restart as Administrator", e)
            self._set_status("Not running as Administrator - physical disks cannot be read. File > Open disk image... still works.")
            return
        self.rescan_disks()

    def rescan_disks(self):
        self._set_status("Looking for disks...")
        self._bg(eb.list_disks, self._disks_loaded)

    def _disks_loaded(self, disks, err):
        if err:
            return self._error("Could not list disks", err)
        self.disks = disks
        self.disk_cb["values"] = [d.describe() + ("   [Windows boot/system disk]" if d.is_boot or d.is_system else "")
                                  for d in disks]
        self.scan_target = None
        if disks:
            self._set_status("Choose the disk that holds your Linux install.")
        else:
            self._set_status("No disks found. (This tool lists disks on Windows; elsewhere use File > Open disk image.)")

    def _disk_selected(self, _event=None):
        i = self.disk_cb.current()
        if i < 0 or i >= len(self.disks):
            return
        n = self.disks[i].number
        self._begin_scan(("disk", n), "Scanning partitions on disk %d..." % n)

    def _scan_image(self, path):
        self.disk_cb.set("Image: " + os.path.basename(path))
        self._begin_scan(("image", path), "Scanning %s..." % os.path.basename(path))

    def _begin_scan(self, target, msg):
        self.part_cb.set("")
        self.part_cb["values"] = []
        self.parts = []
        self._set_status(msg)
        disk_arg = target[1]
        self._bg(lambda: eb.scan_partitions(disk_arg), lambda r, e: self._parts_loaded(target, r, e))

    def _parts_loaded(self, target, parts, err):
        if err:
            self._set_status("Could not read the disk.")
            return self._error("Could not scan partitions", err)
        self.scan_target, self.parts = target, parts
        self.part_cb["values"] = [p.describe() + ("" if p.readable else "   (cannot read)") for p in parts]
        readable = [p for p in parts if p.readable]
        if not parts:
            self._set_status("No partitions found on that disk.")
            return
        best = max(readable, key=lambda p: p.size) if readable else None
        if best is not None:
            self.part_cb.current(parts.index(best))
        self._set_status("Pick a partition and press Open." if len(parts) > 1 else "Opening...")
        if len(parts) == 1 and best is not None:
            self._open_selected_partition()

    def open_image_dialog(self):
        p = filedialog.askopenfilename(parent=self, title="Open a disk image or device file")
        if p:
            self._scan_image(p)

    def _open_selected_partition(self):
        i = self.part_cb.current()
        if i < 0 or i >= len(self.parts) or self.scan_target is None:
            messagebox.showinfo("Open", "Choose a disk and a partition first.", parent=self)
            return
        p = self.parts[i]
        if not p.readable:
            messagebox.showwarning("Cannot read this partition",
                                   "Partition #%d contains: %s\n\nThis tool reads ext2/3/4 only. Encrypted (LUKS) and "
                                   "LVM volumes must be unlocked from Linux itself." % (p.index, p.fs), parent=self)
            return
        kind, target = self.scan_target
        self._set_status("Opening partition #%d..." % p.index)
        kw = {"disk": target} if kind == "disk" else {"image": target}
        self._bg(lambda: eb.open_ext4(offset=p.offset, size=p.size, **kw), self._fs_opened)

    def _fs_opened(self, fs, err):
        if err:
            self._set_status("Could not open the partition.")
            return self._error("Could not open the filesystem", err)
        if self.fs is not None:
            try:
                self.fs.close()
            except Exception:
                pass
        self.fs = fs
        info = fs.info()
        self.fs_label.config(text="%s  |  %s  |  block size %d" % (
            info["label"] or "(no label)", eb.human_size(info["size_bytes"]), info["block_size"]))
        self.hist, self.hpos = [], -1
        self._reset_tree()
        self.goto("/")
        if not fs.clean:
            messagebox.showwarning(
                "Not cleanly unmounted",
                "This Linux filesystem was not shut down cleanly (crash, or a journal that was never replayed).\n\n"
                "Files changed just before the last shutdown may be missing or out of date here.\n"
                "Booting Linux and shutting it down normally fixes that.", parent=self)

    # ---- tree (left) --------------------------------------------------------------------
    def _reset_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.node_path = {}
        label = (self.fs.label or "/") if self.fs else "/"
        self.tree_root = self.tree.insert("", "end", text=label, image=self.icons["folder"], open=True)
        self.node_path[self.tree_root] = "/"
        self.tree.insert(self.tree_root, "end", text="", tags=("dummy",))
        self._populate(self.tree_root)

    def _populate(self, iid):
        kids = self.tree.get_children(iid)
        if not (len(kids) == 1 and "dummy" in self.tree.item(kids[0], "tags")):
            return
        self.tree.delete(kids[0])
        try:
            ents = [e for e in self.fs.listdir(self.node_path[iid]) if e.kind == "dir"]
        except Exception:
            return
        for e in ents:
            if not self.show_hidden.get() and e.name.startswith("."):
                continue
            c = self.tree.insert(iid, "end", text=e.display, image=self.icons["folder"])
            self.node_path[c] = e.path
            self.tree.insert(c, "end", text="", tags=("dummy",))

    def _on_tree_open(self, _event):
        iid = self.tree.focus()
        if iid:
            self._populate(iid)

    def _on_tree_select(self, _event):
        sel = self.tree.selection()
        if sel and self.fs:
            path = self.node_path.get(sel[0])
            if path and path != self.cwd:
                self.goto(path)

    def _reveal(self, path):
        if self.tree_root is None:
            return
        iid, cur = self.tree_root, ""
        self._populate(iid)
        for part in [p for p in path.split("/") if p]:
            cur += "/" + part
            nxt = None
            for c in self.tree.get_children(iid):
                if self.node_path.get(c) == cur:
                    nxt = c
                    break
            if nxt is None:
                break
            iid = nxt
            self._populate(iid)
            self.tree.item(iid, open=True)
        self.tree.selection_set(iid)
        self.tree.see(iid)

    # ---- navigation ---------------------------------------------------------------------
    def goto(self, path, push=True):
        if not self.fs:
            return
        path = posixpath.normpath("/" + path.strip().lstrip("/"))
        try:
            ents = self.fs.listdir(path)
        except Exception as e:
            self.addr_var.set(self.cwd)
            return self._error("Cannot open " + path, e)
        self.cwd = path
        if push:
            del self.hist[self.hpos + 1:]
            self.hist.append(path)
            self.hpos = len(self.hist) - 1
        self.addr_var.set(path)
        self._fill(ents)
        self._reveal(path)
        self._nav_state()

    def back(self):
        if self.hpos > 0:
            self.hpos -= 1
            self.goto(self.hist[self.hpos], push=False)

    def fwd(self):
        if self.hpos < len(self.hist) - 1:
            self.hpos += 1
            self.goto(self.hist[self.hpos], push=False)

    def up(self):
        if self.fs:
            self.goto(posixpath.dirname(self.cwd) or "/")

    def refresh(self):
        if self.fs:
            with self.fs._lock:
                self.fs._dcache.clear()
            self.goto(self.cwd, push=False)

    def _nav_state(self):
        self.btn_back.state(["!disabled"] if self.hpos > 0 else ["disabled"])
        self.btn_fwd.state(["!disabled"] if self.hpos < len(self.hist) - 1 else ["disabled"])
        self.btn_up.state(["!disabled"] if self.cwd != "/" else ["disabled"])

    def _hidden_toggled(self):
        if self.fs:
            self._reset_tree()
            self.goto(self.cwd, push=False)

    # ---- list (right) -------------------------------------------------------------------
    def _sorted(self, items):
        key = {"name": lambda e: e.name.casefold(),
               "modified": lambda e: e.mtime,
               "type": lambda e: (type_text(e), e.name.casefold()),
               "size": lambda e: (e.size, e.name.casefold())}[self.sort_col]
        dirs = sorted([e for e in items if e.kind == "dir"], key=key, reverse=self.sort_rev)
        rest = sorted([e for e in items if e.kind != "dir"], key=key, reverse=self.sort_rev)
        return dirs + rest

    def _fill(self, ents=None):
        if ents is not None:
            self.cur_entries = ents
        items = [e for e in self.cur_entries if self.show_hidden.get() or not e.name.startswith(".")]
        self.entries = self._sorted(items)
        self.lst.delete(*self.lst.get_children())
        for i, e in enumerate(self.entries):
            self.lst.insert("", "end", iid=str(i), text=e.display, image=self.icons.get(e.kind, self.icons["other"]),
                            values=(fmt_time(e.mtime), type_text(e), size_text(e)))
        self._update_status()

    def _sort(self, key):
        if self.sort_col == key:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col, self.sort_rev = key, False
        self._headings()
        self._fill()

    def _selected(self):
        return [self.entries[int(i)] for i in self.lst.selection()]

    def _select_all(self):
        self.lst.selection_set(self.lst.get_children())

    def _update_status(self):
        sel = self._selected()
        text = "%d items" % len(self.entries)
        if sel:
            total = sum(e.size for e in sel if e.kind == "file")
            text += "   |   %d selected" % len(sel) + ("  (%s)" % eb.human_size(total) if total else "")
        self._set_status(text)

    def _context(self, event):
        iid = self.lst.identify_row(event.y)
        if iid and iid not in self.lst.selection():
            self.lst.selection_set(iid)
        try:
            self.menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.menu.grab_release()

    def _on_double(self, event):
        if self.lst.identify_row(event.y):
            self._open_item_selected()

    def _open_item_selected(self):
        sel = self._selected()
        if sel:
            self._open_item(sel[0])

    def _open_item(self, e):
        if e.kind == "dir":
            return self.goto(e.path)
        if e.kind == "symlink":
            try:
                t = self.fs.stat(e.path, follow=True)
            except Exception:
                try:
                    target = self.fs.readlink(e.path)
                except Exception:
                    target = "?"
                return messagebox.showinfo("Link target not found",
                                           "This symbolic link points to:\n%s\n\nThat location is not on this partition." % target,
                                           parent=self)
            if t.kind == "dir":
                return self.goto(e.path)
            e = t if t.kind == "file" else e
        if e.kind == "file":
            self._preview(e)

    # ---- copy / preview --------------------------------------------------------------------
    def _run_copy(self, sources, dest, title, after):
        CopyDialog(self, sources, dest, title, after)

    def copy_selected(self):
        if not self.fs:
            return messagebox.showinfo("Copy", "Open a partition first.", parent=self)
        sel = self._selected()
        if sel:
            sources = [e.path for e in sel]
        else:
            if not messagebox.askyesno("Copy folder", "Nothing is selected.\nCopy the whole current folder?\n\n" + self.cwd,
                                       parent=self):
                return
            sources = [self.cwd]
        dest = filedialog.askdirectory(parent=self, mustexist=False,
                                       title="Copy to... (choose a folder on a Windows drive)")
        if dest:
            self._run_copy(sources, os.path.normpath(dest), "Copying", self._copy_done)

    def _copy_done(self, dest, res, err):
        if err is not None:
            return messagebox.showerror("Copy failed", "%s: %s" % (type(err).__name__, err), parent=self)
        msg = "Copied %d file(s), %s." % (res.copied, eb.human_size(res.bytes))
        if res.cancelled:
            msg = "Cancelled.\n" + msg
        if res.skipped:
            msg += "\nSkipped %d file(s) that were already there." % res.skipped
        if res.renamed:
            msg += "\n%d name(s) were changed because Windows does not allow them." % res.renamed
        if res.special:
            msg += "\n%d link/special file(s) were not copied." % len(res.special)
        if res.failed:
            log = os.path.join(dest, "extfs_copy_errors.txt")
            try:
                with open(log, "w", encoding="utf-8", errors="backslashreplace") as f:
                    for p, m in res.failed:
                        f.write("%s\t%s\n" % (p, m))
            except OSError:
                log = "(could not write log)"
            messagebox.showwarning("Copy finished with errors",
                                   msg + "\n\n%d file(s) FAILED. Details: %s" % (len(res.failed), log), parent=self)
        elif messagebox.askyesno("Copy finished", msg + "\n\nOpen the destination folder?", parent=self):
            try:
                open_with_os(dest)
            except Exception as e:
                self._error("Could not open folder", e)

    def _preview(self, e):
        if e.encrypted:
            return messagebox.showwarning("Encrypted file",
                                          "This file is encrypted by Linux (fscrypt/eCryptfs) and cannot be read here.",
                                          parent=self)
        if e.size > 200 * 1024 * 1024 and not messagebox.askyesno(
                "Large file", "%s is %s.\nCopy it to a temporary folder and open it?" % (e.display, eb.human_size(e.size)),
                parent=self):
            return
        tmp = tempfile.mkdtemp(prefix="extfs_preview_")
        self.tmp_dirs.append(tmp)

        def done(dest, res, err):
            if err is not None:
                return self._error("Could not open file", err)
            names = [n for n in os.listdir(dest) if not n.endswith(".part")]
            if res.failed or not names:
                return messagebox.showerror("Could not open file", "\n".join(m for _p, m in res.failed) or "Nothing was copied.",
                                            parent=self)
            try:
                open_with_os(os.path.join(dest, names[0]))
            except Exception as ex:
                self._error("No program could open this file", ex)
        self._run_copy([e.path], tmp, "Opening " + e.display, done)

    def _copy_path(self):
        sel = self._selected()
        path = sel[0].path if sel else self.cwd
        self.clipboard_clear()
        self.clipboard_append(path)

    def _properties(self):
        sel = self._selected()
        if not sel:
            return
        e = sel[0]
        lines = ["Name:      %s" % e.display, "Path:      %s" % e.path, "Type:      %s" % type_text(e)]
        if e.kind in ("file", "symlink"):
            lines.append("Size:      %s (%d bytes)" % (eb.human_size(e.size), e.size))
        if e.kind == "symlink":
            try:
                lines.append("Points to: %s" % self.fs.readlink(e.path))
            except Exception:
                pass
        lines += ["Modified:  %s" % fmt_time(e.mtime), "Mode:      %s (%o)" % (stat.filemode(e.mode), e.mode & 0o7777),
                  "Inode:     %d" % e.ino]
        if e.encrypted:
            lines.append("Encrypted: yes (cannot be read here)")
        messagebox.showinfo("Properties", "\n".join(lines), parent=self)

    def _about(self):
        messagebox.showinfo(
            "About / limits",
            "Read-only: nothing is ever written to the Linux disk.\n\n"
            "Reads ext2/ext3/ext4. Not supported: encrypted partitions (LUKS), LVM, btrfs, "
            "and files encrypted by Linux (home-folder encryption / eCryptfs / fscrypt).\n\n"
            "If Linux was not shut down cleanly, the newest changes may be missing.\n"
            "Symbolic links are skipped when copying folders; Windows-illegal file names "
            "are renamed (e.g. a:b -> a_b).", parent=self)

    def _quit(self):
        for d in self.tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)
        if self.fs is not None:
            try:
                self.fs.close()
            except Exception:
                pass
        self.destroy()


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Read-only ext2/3/4 explorer")
    ap.add_argument("image", nargs="?", help="optional disk image file to open")
    a = ap.parse_args()
    App(a.image).mainloop()


if __name__ == "__main__":
    main()
