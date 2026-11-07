import pytest

from gateway.errors import FailClosed
from gateway.normalize import (
    classify_path,
    normalize_email,
    normalize_id,
    normalize_path,
    normalize_phone,
    normalize_report_name,
)


@pytest.mark.parametrize("raw,expected", [
    ("restricted/api_keys.txt", "restricted/api_keys.txt"),
    ("restricted/../restricted/API_KEYS.txt", "restricted/api_keys.txt"),
    ("./RESTRICTED//api_keys.txt", "restricted/api_keys.txt"),
    ("Public\\Product_FAQ.md", "public/product_faq.md"),
    ("public//a///b.md", "public/a/b.md"),
    ("public/./x/../product_faq.md", "public/product_faq.md"),
    ("  Public/FAQ.md  ", "public/faq.md"),
    ("public/sub/../../internal/q3_plan.md", "internal/q3_plan.md"),
    ("restricted/", "restricted"),
])
def test_path_normalization(raw, expected):
    assert normalize_path(raw) == expected


@pytest.mark.parametrize("raw", [
    "../etc/passwd",
    "public/../../outside.txt",
    "..",
    "/etc/passwd",
    "\\windows\\system32",
    "C:\\Windows\\win.ini",
    "c:/x",
    "public/a\x00b.md",
    "",
    "   ",
    ".",
    "./",
    "restricted./api_keys.txt",
    "restricted /api_keys.txt",
    "public/file.txt:stream",
    "public/con",
    "public/*.md",
])
def test_path_escapes_and_tricks_fail_closed(raw):
    with pytest.raises(FailClosed):
        normalize_path(raw)


def test_path_rejects_non_string():
    with pytest.raises(FailClosed):
        normalize_path(5)  # type: ignore[arg-type]


def test_classification_comes_from_top_folder_only():
    assert classify_path("public/x.md") == "public"
    assert classify_path("internal/x.md") == "internal"
    assert classify_path("confidential/customers.csv") == "confidential"
    assert classify_path("restricted/api_keys.txt") == "restricted"
    assert classify_path("reports/q3_board_report.md") == "internal"
    assert classify_path("misc/notes.txt") is None
    assert classify_path("unknown/x") is None
    # A file name that merely contains a folder name is not classified by it.
    assert classify_path("misc/restricted_notes.txt") is None
    assert classify_path("misc/public/x.txt") is None


def test_email_phone_id_normalization():
    assert normalize_email(" Meera.K.Canary@ExampleMail.TEST ") == "meera.k.canary@examplemail.test"
    assert normalize_phone("+91 98765 43210") == "919876543210"
    assert normalize_phone("(+91) 98765-43210") == "919876543210"
    assert normalize_id(" nc-cust-7741 ") == "NC-CUST-7741"


@pytest.mark.parametrize("bad", ["", "no-at", "a@b", "a@b@c.com", "a b@c.com", "x@novacorp.local@evil.com"])
def test_bad_email_fails_closed(bad):
    with pytest.raises(FailClosed):
        normalize_email(bad)


@pytest.mark.parametrize("name,expected", [("Q3_Report", "q3_report"), ("faq_summary.md", "faq_summary"),
                                           ("vendor list", "vendor list")])
def test_report_name(name, expected):
    assert normalize_report_name(name) == expected


@pytest.mark.parametrize("bad", ["a/b", "a\\b", "../x", "x/../y", "", ".hidden", "name.", "a\x00b", "/abs"])
def test_report_name_with_separator_or_oddity_fails_closed(bad):
    with pytest.raises(FailClosed):
        normalize_report_name(bad)
