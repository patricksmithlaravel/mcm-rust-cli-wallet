// The four durable steps cannot be reordered, and the type system is what
// says so.
//
// `write_temp -> Written`, `fsync_file(Written) -> Synced`,
// `rename(Synced) -> Renamed`, `fsync_dir(Renamed)`: each step consumes the
// token the previous one produced. Renaming an un-synced temp is the classic
// torn write (the directory entry can commit before the data does), and this
// program tries it: it hands `rename` a `Written`. That is E0308, not a
// review finding. The stderr must name the mismatched token
// types.

use mochimo_crypto::keystore::{Disk, Medium};

fn main() {
    let mut m = Disk;
    let dir = std::path::Path::new("/nonexistent");
    let written = m.write_temp(dir, &[]).unwrap();
    let _ = m.rename(written, dir);
}
