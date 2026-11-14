"""Puts the descriptions of a generated playbook in place: what each section shows and what each step runs and why.

A step or section gives its description inline (desc=… / "description") or in the generator's DESCRIPTIONS /
SECTION_DESCRIPTIONS; every one must end with one, and every id of those dicts must exist, or the generator stops.
"""


def _with_description(item, text):
    """The item with "description" right after "title" (the page and the evidence read it there)."""
    out = {}
    for key, value in item.items():
        if key == "description":
            continue
        out[key] = value
        if key == "title":
            out["description"] = text
    return out


def describe(sections, steps, section_texts=None):
    section_texts = section_texts or {}
    used, missing = set(), []
    result = []
    for section in sections:
        text = section.get("description") or section_texts.get(section["id"])
        if section["id"] in section_texts:
            used.add("section:" + section["id"])
        if not text:
            missing.append("section " + section["id"])
        described = []
        for step in section["steps"]:
            step_text = step.get("description") or steps.get(step["id"])
            if step["id"] in steps:
                used.add(step["id"])
            if not step_text:
                missing.append("step " + step["id"])
            described.append(_with_description(step, step_text) if step_text else step)
        result.append({**(_with_description(section, text) if text else section), "steps": described})
    unknown = [k for k in steps if k not in used] + [k for k in section_texts if "section:" + k not in used]
    if missing or unknown:
        raise SystemExit("Descriptions: missing for " + ", ".join(missing) + "; unknown ids " + ", ".join(unknown))
    return result
