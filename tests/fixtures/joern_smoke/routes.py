from service import execute


def route(request):
    command = request.args.get("cmd")
    return execute(command)
