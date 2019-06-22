from . import bp_flow

from assetscube.authentication import auth as a

@bp_flow.route('/flow')
def flow():
    print(a.nat())
    print("inside flow")
    return 'flow'