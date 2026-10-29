// The upgrade `detail` old clients see. A leaf file still holding the
// retired 2400-byte expanded ML-KEM key is refused with exactly this sentence.
export const UPGRADE_DETAIL =
	"This rine account uses the retired client_secret sign-in. rine now derives every key from an org root with a recovery phrase. Upgrade your rine package to the latest version and run onboarding again; your previous org and its messages are not carried over.";
