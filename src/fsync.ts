/**
 * Durability for a file or directory entry that something irreversible follows.
 *
 * A rename, a hard link or an unlink survives a power loss only once the file's
 * data and its directory entry have both reached the disk. The escrow store uses
 * these before it deletes the state a sealed export came from.
 */
import * as fs from "node:fs";

/** Flush a file's data to disk. */
export function fsyncFile(path: string): void {
	const fd = fs.openSync(path, "r");
	try {
		fs.fsyncSync(fd);
	} finally {
		fs.closeSync(fd);
	}
}

/**
 * Flush a directory's entries to disk. Best effort: a platform that cannot open
 * a directory for reading has no directory sync to give.
 */
export function fsyncDir(path: string): void {
	let fd: number;
	try {
		fd = fs.openSync(path, "r");
	} catch {
		return;
	}
	try {
		fs.fsyncSync(fd);
	} catch {
		// Not supported on this filesystem: the data sync above is all there is.
	} finally {
		fs.closeSync(fd);
	}
}
