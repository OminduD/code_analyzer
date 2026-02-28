def safe_recursive_call(n):
    if n <= 0:
        return 0
    return n + safe_recursive_call(n - 1)

def uncontrolled_recursive_call(n):
    return n + uncontrolled_recursive_call(n + 1)
