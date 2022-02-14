import json

def isExistKeyInObj(key, obj):
    try:
        if isinstance(obj, dict):
            return isExistKeyInDict(key, obj)
        else:
            return isExistKeyInJson(key, obj)
    except Exception:
        return False

def isExistKeyInDict(key, data):
    try:
        if key in data:
            return True
        else:
            return False
    except Exception:
        return False

def isExistKeyInJson(key, data):
    try:
        if isinstance(data, str):
            res = json.loads(data)
        else:
            res = data
        if not (res.get(key) is None):
            return True
        else:
            return False
    except Exception:
        return False