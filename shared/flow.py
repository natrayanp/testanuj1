from . import bp_shared

from nawalcube_server.authentication import auth as a

@bp_shared.route('/panvali')
def panvali():
    print("inside panvali")
    return 'panvali'