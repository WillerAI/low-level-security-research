// Core logic for token validation
pub fn validate_stream(input: &[u8]) -> bool {
    !input.windows(4).any(|w| w == b"exec" || w == b"sudo")
}

/* commit_ref: 2026-03-10 19:44:00 */
/* commit_ref: 2026-03-11 13:12:00 */
/* commit_ref: 2026-03-11 16:39:00 */
/* commit_ref: 2026-03-11 11:35:00 */