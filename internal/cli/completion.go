package cli

import (
	"errors"
	"fmt"
	"strings"
)

func (a app) completion(args []string) error {
	if len(args) != 1 || (args[0] != "bash" && args[0] != "zsh") {
		return errors.New("usage: wirectl connect completion bash|zsh")
	}
	script := bashCompletion
	if args[0] == "zsh" {
		script = zshCompletion
	}
	_, err := fmt.Fprint(a.out, strings.Replace(script, "# CORE", completionCore, 1))
	return err
}

// Only public command metadata is completed. No daemon, state files, credentials,
// enrollment tokens, or pairing codes are consulted during completion.
// The zsh wrapper enables zero-based arrays locally for this shared parser.
const completionCore = `
_wirectl_connect_candidates() {
    local -a args
    args=("$@")
    local count=${#args[@]} i token pending='' command=connect start=0 ended=0
    local common='--state-dir --name --help' options='' current
    _wc_candidates=()
    _wc_kind=''
    _wc_prefix=''
    _wc_value=''
    (( count )) || return 0
    current="${args[count-1]}"
    case "${args[0]}" in
        login|resume|status|list|stop|delete|remove|doctor|serve|completion|setup|update|help|version)
            command="${args[0]}"; start=1 ;;
    esac
    # A command is selected only in the first position, as in the actual CLI.
    if (( count == 1 )); then
        start=0
        command=connect
    fi
    for ((i=start; i<count-1; i++)); do
        token="${args[i]}"
        if [[ -n "$pending" ]]; then
            # Bash's default COMP_WORDBREAKS splits --option=value at '='.
            [[ "$token" == '=' ]] && continue
            pending=''
            continue
        fi
        [[ "$token" == '--' ]] && { ended=1; break; }
        case "$token" in
            --state-dir|--name|--pin|--network|--interface|--mtu|--stun|--code|--domain|--listen|--stun-listen|--cert|--key|--enrollment-token-file|--max-relay-connections|--relay-bytes-per-second|--archive|--checksums|--manifest|--version)
                pending="$token" ;;
        esac
    done
    (( ended )) && return 0
    if [[ "$current" == --*=* ]]; then
        pending="${current%%=*}"
        _wc_prefix="$pending="
        current="${current#*=}"
    elif [[ "$current" == '=' && -n "$pending" ]]; then
        current=''
    fi
    if [[ -n "$pending" ]]; then
        _wc_value="$current"
        case "$pending" in
            --state-dir) _wc_kind=directory ;;
            --cert|--key|--enrollment-token-file) [[ "$command" == serve ]] && _wc_kind='file' ;;
            --archive|--checksums|--manifest) [[ "$command" == update ]] && _wc_kind='file' ;;
        esac
        return 0
    fi
    case "$command" in
        connect|resume) options="$common --background --foreground --network --interface --mtu --stun --relay-only --verbose --code --replace" ;;
        login) options="$common --pin" ;;
        stop) options="$common --uninstall" ;;
        status|list) options="$common --watch --json --all" ;;
        delete|remove) options="$common" ;;
        doctor) options="$common" ;;
        update) options='--version --archive --checksums --manifest --state-dir --help' ;;
        serve) options="$common --domain --http --listen --stun-listen --cert --key --enrollment-token-file --init --max-relay-connections --relay-bytes-per-second" ;;
        completion) options='bash zsh' ;;
    esac
    if [[ "$current" == -* ]]; then
        [[ "$command" == completion ]] && options=''
    elif (( count == 1 )); then
        options='login resume status list stop delete remove doctor serve completion setup update help version'
    elif [[ "$command" != completion || "$count" != 2 ]]; then
        options=''
    fi
    # Metadata contains only fixed ASCII words; splitting does not interpret input.
    local candidate
    for candidate in $options; do
        [[ "$candidate" == "$current"* ]] && _wc_candidates+=("$candidate")
    done
    return 0
}
`

const bashCompletion = `# bash completion for wirectl connect and wirectl-connect.
# Load after wirectl download completion, if installed.
# CORE
_wirectl_connect_completion() {
    local program="${COMP_WORDS[0]##*/}" offset=1 match
    local -a _wc_candidates
    local _wc_kind _wc_prefix _wc_value
    COMPREPLY=()
    if [[ "$program" == wirectl ]]; then
        if (( COMP_CWORD == 1 )); then
            while IFS= read -r match; do COMPREPLY+=("$match"); done < <(compgen -W 'connect download version help' -- "${COMP_WORDS[COMP_CWORD]}")
            return 0
        fi
        if [[ "${COMP_WORDS[1]}" == download ]]; then
            if declare -F _wirectl_download_completion >/dev/null; then _wirectl_download_completion; fi
            return 0
        fi
        [[ "${COMP_WORDS[1]}" == connect ]] || return 0
        offset=2
    fi
    _wirectl_connect_candidates "${COMP_WORDS[@]:offset:COMP_CWORD-offset+1}"
    if [[ -n "$_wc_kind" ]]; then
        local flag=-f
        [[ "$_wc_kind" == directory ]] && flag=-d
        # Readline replaces only the text after '=' with its default word breaks,
        # even on Bash versions that retain the entire word in COMP_WORDS.
        [[ "$COMP_WORDBREAKS" == *'='* ]] && _wc_prefix=''
        while IFS= read -r match; do COMPREPLY+=("$_wc_prefix$match"); done < <(compgen "$flag" -- "$_wc_value")
        compopt -o filenames 2>/dev/null || :
    else
        COMPREPLY=("${_wc_candidates[@]}")
    fi
    return 0
}
complete -o filenames -F _wirectl_connect_completion wirectl wirectl-connect
`

const zshCompletion = `# zsh completion for wirectl connect and wirectl-connect.
# Load after compinit and wirectl download completion, if installed.
# CORE
_wirectl_connect_completion() {
    local program="${words[1]##*/}" offset=2
    if [[ "$program" == wirectl ]]; then
        if (( CURRENT == 2 )); then
            compadd -- connect download version help
            return
        fi
        if [[ "${words[2]}" == download ]]; then
            if (( $+functions[_wirectl_download_completion] )); then _wirectl_download_completion; fi
            return
        fi
        [[ "${words[2]}" == connect ]] || return
        offset=3
    fi
    local -a input _wc_candidates
    local _wc_kind _wc_prefix _wc_value
    input=("${words[@][$offset,$CURRENT]}")
    # Keep zsh's native completion functions in their normal option environment.
    () {
        emulate -L zsh
        setopt KSH_ARRAYS SH_WORD_SPLIT
        _wirectl_connect_candidates "$@"
    } "${input[@]}"
    if [[ -n "$_wc_kind" ]]; then
        if [[ -n "$_wc_prefix" ]]; then
            # Move the option prefix into IPREFIX before zsh completes paths.
            compset -P '*=' || return
        fi
        if [[ "$_wc_kind" == directory ]]; then _files -/; else _files; fi
    else
        compadd -a _wc_candidates
    fi
}
compdef _wirectl_connect_completion wirectl wirectl-connect
`
