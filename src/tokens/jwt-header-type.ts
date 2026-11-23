/** The `typ` header values the service signs with (an ID token carries none). */
export enum JwtHeaderType
{
    /** An RFC 9068 access token. */
    AccessToken = 'at+jwt',
}
