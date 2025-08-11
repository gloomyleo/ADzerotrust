
@{ LDAPSigningEnforced = $null; ChannelBinding = $null; SMBSigningRequired = $null; Hint = 'Verify domain/DC policies for LDAP & SMB signing' } | ConvertTo-Json -Compress
