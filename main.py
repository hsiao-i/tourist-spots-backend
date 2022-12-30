import datetime

import flask
from flask import Flask, jsonify, request, session
from flask_login import LoginManager, UserMixin, login_user, current_user, AnonymousUserMixin, logout_user, \
    login_required
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required, get_jwt, \
    create_refresh_token
import os

# import redis
# from flask_session import Session

app = Flask(__name__)
app.app_context().push()

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tourist-spot.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///tourist-spot.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
db = SQLAlchemy(app)
# db.init_app(app)
migrate = Migrate(app, db)

jwt = JWTManager()
# 設定 JWT 密鑰
app.config['JWT_SECRET_KEY'] = '48daa819eb2b4ec190627f4b8331f0ea'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
# app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(days=30)

jwt = JWTManager(app)
jwt.init_app(app)

# CORS(app)
cors = CORS(app, resources={r"/api/*": {"origins": "*"}})

login_manager = LoginManager()
login_manager.init_app(app)


# f_session = Session()
# app.config['SESSION_USE_SIGNER'] = True  # 是否对发送到浏览器上session的cookie值进行加密
# app.config['SESSION_TYPE'] = 'redis'  # session类型为redis
# app.config['SESSION_KEY_PREFIX'] = 'session:'  # 保存到session中的值的前缀
# app.config['PERMANENT_SESSION_LIFETIME'] = 7200  # 失效时间 秒
# # app.config['SESSION_REDIS'] = redis.Redis(host='127.0.0.1', port='6379', db=4)  # redis数据库连接
# app.config['SESSION_REDIS'] = redis.Redis(host='127.0.0.1', db=4)  # redis数据库连接
# f_session.init_app(app)

# login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    # return User.query.filter_by(username=user_id).first()


class TouristSpot(db.Model):
    __tablename__ = "tourist_spot"
    id = db.Column(db.Integer, primary_key=True)
    position = db.Column(db.String(250), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}
    # to_dict(self)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    favorite_spots = relationship("FavoriteTouristSpot", back_populates="spot_user", cascade="all, delete-orphan")

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


class FavoriteTouristSpot(db.Model):
    __tablename__ = "favorite_spots"
    id = db.Column(db.Integer, primary_key=True)
    add_favorite_id = db.Column(db.Integer)

    spot_user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    spot_user = relationship("User", back_populates="favorite_spots")

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}


db.create_all()

# new_tourist_spot = TouristSpot(position="情人湖湖湖2", description="旅遊景點12", img_url="2https://www.com1")
# new_user = User(email="qq123@gmail.com", password="1123", name="Amy23")
# db.session.add(new_tourist_spot)
# db.session.commit()

new_favorite = FavoriteTouristSpot(
    add_favorite_id=1,
    spot_user_id=6
)
db.session.add(new_favorite)


# db.session.commit()
# try:
#     db.session.add(new_tourist_spot)
#     db.session.commit()
# except IntegrityError:
#     db.session.rollback()

# spot = TouristSpot.query.filter_by(position="情人湖湖湖").first()
# print(spot)


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/api/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.get_json()
        hash_and_salt_password = generate_password_hash(
            data.get("password"),
            method="pbkdf2:sha256",
            salt_length=8
        )
        new_user = User(
            name=data.get("username"),
            email=data.get("useremail"),
            password=hash_and_salt_password,
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return jsonify(success={"success": "成功註冊"})


# 登入
@app.route('/api/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.json.get("useremail")
        password = request.json.get("password")
        # email = "test1@gmail.com"
        # password = "qwerasdzz"

        user = User.query.filter_by(email=email).first()
        if not user:
            return jsonify(error={"status": 401, "error": "查無此 email 的帳號"}), 401
        elif not check_password_hash(user.password, password):
            return jsonify(error={"status": 401, "error": "密碼有誤"}), 401
        else:
            print(user.favorite_spots, user.email)
            access_token = create_access_token(identity={"username": user.name, "userid": user.id}, fresh=True)
            refresh_token = create_refresh_token(identity={"username": user.name, "userid": user.id})
            login_user(user)
            session["id"] = user.id
            session["is_logged"] = True
            print(session["id"], session["is_logged"])
            # access_token = create_access_token(identity=get_jwt()['exp'])
            return jsonify(success={"status": 200, "success": "成功登入", "access_token": access_token,
                                    "refresh_token": refresh_token, "user_id": user.id})


# refresh token
@app.route("/api/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    access_token = create_access_token(identity=identity, fresh=True)
    return jsonify(access_token=access_token)


# 如果使用者沒有登入
# class Anonymous(AnonymousUserMixin):
#     def __init__(self):
#         self.username = "訪客"


# 確認登入
@app.route("/api/check-login", methods=["POST"])
@jwt_required()
def check_login():
    try:
        exp = get_jwt()['exp']
        print(exp)
        return jsonify(success={"success": "確認登入"})

    except:
        return jsonify(error={"error": "請重新登入"})


# 登出
@app.route("/api/logout")
def logout():
    session.clear()
    logout_user()
    return jsonify(success={"success": "成功登出"})


# 取得全部景點
@app.route('/api/tourist-spots')
def get_all_tourist_spots():
    spots = db.session.query(TouristSpot).all()
    return jsonify(spots=[spot.to_dict() for spot in spots])


# 取得單筆資料
@app.route('/api/tourist-spot/<int:tourist_spot_id>')
def get_tourist_spot(tourist_spot_id):
    tourist_spot = db.session.query(TouristSpot).get(tourist_spot_id)
    return jsonify(spot=tourist_spot.to_dict())


# 新增景點
@app.route('/api/add-tourist-spot', methods=["GET", "POST"])
def add_tourist_spot():
    data = request.get_json()
    new_spot = TouristSpot(
        position=data.get("position"),
        description=data.get("description"),
        img_url=data.get("img_url")
    )
    db.session.add(new_spot)
    db.session.commit()
    print(current_user)
    return jsonify(success={"success": "成功建立景點"})


# 編輯景點 put
@app.route('/api/revise-tourist-spot/<int:tourist_spot_id>', methods=["PUT"])
def revise_tourist_spot(tourist_spot_id):
    data = request.get_json()

    position = data.get("position")
    description = data.get("description")
    img_url = data.get("img_url")

    revise_spot = db.session.query(TouristSpot).get(tourist_spot_id)
    # print(revise_spot.position)

    if revise_spot:
        revise_spot.position = position
        revise_spot.description = description
        revise_spot.img_url = img_url
        # print(revise_spot.description)
        db.session.commit()
        return jsonify(success={"success": "成功更新景點資料"})


# 刪除單筆景點
@app.route('/api/delete-tourist-spot/<int:tourist_spot_id>', methods=["DELETE"])
def delete_tourist_spot(tourist_spot_id):
    delete_spot = db.session.query(TouristSpot).get(tourist_spot_id)
    print(delete_spot)

    if delete_spot:
        db.session.delete(delete_spot)
        db.session.commit()
        return jsonify(success={"success": "成功刪除"})
    else:
        return jsonify(error={"Not Found": "請填入正確 id"}), 400

    return jsonify(error={"Forbidden": "無法刪除"})


# 加入收藏
@app.route('/api/add-favorite/<int:tourist_spot_id>', methods=['POST'])
@jwt_required()
def add_favorite(tourist_spot_id):
    identity = get_jwt_identity()  # 從 jwt 取得身分資訊
    user = User.query.filter_by(id=identity["userid"]).first()
    added_spots = [spot.add_favorite_id for spot in user.favorite_spots]
    # print(identity)

    # if tourist_spot_id in added_spots:
    #     return jsonify(error={"error": "不可重複加入景點"}), 400
    # else:
    new_favorite_spot = FavoriteTouristSpot(
        add_favorite_id=tourist_spot_id,
        spot_user=user,
        spot_user_id=identity["userid"]
    )

    db.session.add(new_favorite_spot)
    db.session.commit()
    print(added_spots)
    return jsonify(success={"success": "成功將景點加入收藏", "added_favorite_id": added_spots})


# 刪除單一收藏
@app.route('/api/delete-favorite/<int:tourist_spot_id>', methods=['DELETE'])
@jwt_required()
def remove_favorite(tourist_spot_id):
    identity_id = get_jwt_identity()["userid"]
    favorite_spot = FavoriteTouristSpot.query.filter_by(add_favorite_id=tourist_spot_id,
                                                        spot_user_id=identity_id).first()
    # user = db.session.query(User).filter_by(id=identity_id).first()
    # user.favorite_spots.remove(favorite_spot)
    print(favorite_spot.spot_user_id)
    db.session.delete(favorite_spot)
    db.session.commit()

    return jsonify(success={"success": "成功移除收藏"})


# 取得收藏列表
@app.route('/api/get-favorite')
@jwt_required()
def get_favorite():
    identity_id = get_jwt_identity()["userid"]
    user = User.query.filter_by(id=identity_id).first()
    user_favorite_spot = []
    # if len(user_favorite_spot) == 0:
    #     return jsonify(favorite=[])

    for spot in user.favorite_spots:
        single_spot = TouristSpot.query.filter_by(id=spot.add_favorite_id).first()
        user_favorite_spot.append(single_spot)
    return jsonify(favorite=[spot.to_dict() for spot in user_favorite_spot])


if __name__ == "__main__":
    app.run(debug=True)
