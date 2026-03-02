"""Pure Python Aho-Corasick multi-pattern matcher."""

from __future__ import annotations

from collections import deque, namedtuple

Match = namedtuple("Match", ["start", "end", "pattern_id", "matched_text"])


class AhoCorasickMatcher:
    def __init__(self, patterns: dict[str, str], *, case_insensitive: bool = False):
        self._case_insensitive = bool(case_insensitive)
        self._patterns: dict[str, str] = {
            key: (value.lower() if self._case_insensitive else value)
            for key, value in patterns.items()
            if isinstance(key, str) and isinstance(value, str) and value != ""
        }
        self._goto: list[dict[str, int]] = [{}]
        self._fail: list[int] = [0]
        self._output: list[list[str]] = [[]]
        self._lengths: dict[str, int] = {key: len(value) for key, value in self._patterns.items()}
        self._built = False
        if self._patterns:
            self.build()

    def build(self) -> None:
        self._goto = [{}]
        self._fail = [0]
        self._output = [[]]
        for pattern_id, pattern in self._patterns.items():
            state = 0
            for ch in pattern:
                nxt = self._goto[state].get(ch)
                if nxt is None:
                    nxt = len(self._goto)
                    self._goto[state][ch] = nxt
                    self._goto.append({})
                    self._fail.append(0)
                    self._output.append([])
                state = nxt
            self._output[state].append(pattern_id)

        queue: deque[int] = deque()
        for _char, state in self._goto[0].items():
            self._fail[state] = 0
            queue.append(state)

        while queue:
            state = queue.popleft()
            for ch, next_state in self._goto[state].items():
                queue.append(next_state)
                fail_state = self._fail[state]
                while fail_state and ch not in self._goto[fail_state]:
                    fail_state = self._fail[fail_state]
                self._fail[next_state] = self._goto[fail_state].get(ch, 0)
                inherited = self._output[self._fail[next_state]]
                if inherited:
                    self._output[next_state].extend(inherited)

        self._built = True

    def search(self, text: str) -> list[Match]:
        if not self._patterns or not isinstance(text, str) or text == "":
            return []
        if not self._built:
            self.build()
        haystack = text.lower() if self._case_insensitive else text
        matches: list[Match] = []
        state = 0
        for idx, ch in enumerate(haystack):
            while state and ch not in self._goto[state]:
                state = self._fail[state]
            state = self._goto[state].get(ch, 0)
            outputs = self._output[state]
            if not outputs:
                continue
            for pattern_id in outputs:
                pattern_len = self._lengths[pattern_id]
                start = idx - pattern_len + 1
                end = idx + 1
                matches.append(
                    Match(
                        start=start,
                        end=end,
                        pattern_id=pattern_id,
                        matched_text=text[start:end],
                    )
                )
        return matches

    def search_first(self, text: str) -> Match | None:
        found = self.search(text)
        if not found:
            return None
        return found[0]
