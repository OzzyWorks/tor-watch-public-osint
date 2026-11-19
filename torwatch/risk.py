import re
HIGH={"password","credential","credentials","api key","secret","credit card","ransomware","stealer"}
def score(text,keywords,assets):
    t=text.lower(); points=0; reasons=[]
    for k in keywords:
        n=len(re.findall(re.escape(k.lower()),t))
        if n:
            points+=min((12 if k.lower() in HIGH else 6)*n,30); reasons.append(f"keyword:{k} x{n}")
    for category,values in (assets or {}).items():
        for v in values or []:
            n=len(re.findall(re.escape(str(v).lower()),t))
            if n:
                points+=min((25 if category=="emails" else 18)*n,40); reasons.append(f"asset:{category}:{v}")
    return min(points,100),reasons
