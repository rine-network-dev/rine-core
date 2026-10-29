/** What a filesystem without hard links (some network and FUSE mounts) answers `link` with. */
const NO_HARD_LINKS = new Set([
	"EPERM",
	"ENOTSUP",
	"EOPNOTSUPP",
	"EXDEV",
	"ENOSYS",
]);

/** Whether a failed `link` means the filesystem has no hard links. */
export function refusesHardLinks(error: unknown): boolean {
	return NO_HARD_LINKS.has((error as NodeJS.ErrnoException).code ?? "");
}
