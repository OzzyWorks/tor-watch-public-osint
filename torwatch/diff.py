import difflib
def excerpt(old,new,limit=1800):
    lines=[]
    for line in difflib.unified_diff(old.split(),new.split(),n=2):
        if not line.startswith(("+++","---","@@")) and line.startswith("+"): lines.append(line)
    return " ".join(lines)[:limit]
