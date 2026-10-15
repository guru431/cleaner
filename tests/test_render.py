from markupsafe import Markup

from cleaner.core.pipeline import sanitize
from cleaner.core.restore import Segment
from cleaner.core.types import Settings
from cleaner.storage.repo import Item
from cleaner.web import render


def test_text_and_attributes_are_escaped():
    html = render.highlight('<b>"x"</b> & <script>', [(0, 3, {"class": "t-PERSON", "title": '"><script>'})])
    assert html == Markup(
        '<mark class="t-PERSON" title="&#34;&gt;&lt;script&gt;">&lt;b&gt;</mark>&#34;x&#34;&lt;/b&gt; &amp; &lt;script&gt;'
    )


def test_overlapping_marks_keep_the_text_whole():
    html = render.highlight("abcdef", [(0, 4, {"class": "a"}), (2, 6, {"class": "b"})])
    assert html == Markup('<mark class="a">abcd</mark>ef')


def test_marks_of_both_panels_point_at_the_same_fragments(state):
    text = "почта a@x.example и 10.1.2.5"
    result = sanitize(state, text, Settings())
    assert len(result.spans) == 2
    spans = [{"start": s.start, "end": s.end, "entity_id": s.entity_id, "surrogate": s.surrogate} for s in result.spans]
    item = Item("i", 1, "input", text, result.sanitized, spans)
    original = render.original_marks(item, state)
    sanitized = render.sanitized_marks(item, state, [])
    assert [text[start:end] for start, end, _ in original] == [text[s.start:s.end] for s in result.spans]
    assert [result.sanitized[start:end] for start, end, _ in sanitized] == [s.surrogate for s in result.spans]
    assert [a["data-entity"] for _, _, a in original] == [a["data-entity"] for _, _, a in sanitized]


def test_restored_segments_are_named():
    [(start, end, attrs)] = render.restored_marks([Segment(0, 5, "unknown")])
    assert (start, end, attrs["class"], attrs["title"]) == (0, 5, "r-unknown", "неизвестная метка")
