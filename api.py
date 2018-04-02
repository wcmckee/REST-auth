#!/usr/bin/env python
import os
from flask import Flask, abort, request, jsonify, g, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

import requests
import shutil
import os
import getpass
from urllib.parse import urlparse
import PIL
import json
from PIL import ImageDraw, ImageFont
from PIL import Image
from PIL import ImageDraw
from flask_bootstrap import Bootstrap
import tweepy
from flask import jsonify
import arrow
import glob
myusr = getpass.getuser()
# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/api/creatememe')
@auth.login_required
def get_resource():
    memename = request.json.get('memename')

    toptext = request.json.get('toptext')
    toptext = toptext.upper()

    bottomtext = request.json.get('bottomtext')
    bottomtext = bottomtext.upper()
    user= request.json.get('user')

    timnow = arrow.now()
    timstr = timnow.timestamp

    galdirdir = '/home/{}/artctrl/meme/galleries/{}/'.format(myusr, user)



    #with open('/home/{}/rbnz-tech-backup/artctrl/meme/galleries/default')

    img = Image.open('/home/{}/artctrl/meme/galleries/default/{}.jpg'.format(myusr, memename))

    imageSize = img.size

    # find biggest font size th90t works
    fontSize = int(imageSize[1]/5)
    font = ImageFont.truetype("/home/{}/Downloads/impact.ttf".format(myusr), fontSize)
    topTextSize = font.getsize(toptext)
    bottomTextSize = font.getsize(bottomtext)

    while topTextSize[0] > imageSize[0]-20 or bottomTextSize[0] > imageSize[0]-20:
        fontSize = fontSize - 1
        font = ImageFont.truetype("/home/{}/Downloads/impact.ttf".format(myusr), fontSize)
        topTextSize = font.getsize(toptext)
        bottomTextSize = font.getsize(bottomtext)

    # find top centered position for top text
    topTextPositionX = (imageSize[0]/2) - (topTextSize[0]/2)
    topTextPositionY = 0
    topTextPosition = (topTextPositionX, topTextPositionY)

    # find bottom centered position for bottom text
    bottomTextPositionX = (imageSize[0]/2) - (bottomTextSize[0]/2)
    bottomTextPositionY = imageSize[1] - bottomTextSize[1] -10
    bottomTextPosition = (bottomTextPositionX, bottomTextPositionY)

    draw = ImageDraw.Draw(img)

    outlineRange = int(fontSize/15)
    for x in range(-outlineRange, outlineRange+1):
        for y in range(-outlineRange, outlineRange+1):
                draw.text((topTextPosition[0]+x, topTextPosition[1]+y), toptext, (0,0,0), font=font)
                draw.text((bottomTextPosition[0]+x, bottomTextPosition[1]+y), bottomtext, (0,0,0), font=font)

        draw.text(topTextPosition, toptext, (255,255,255), font=font)
        draw.text(bottomTextPosition, bottomtext, (255,255,255), font=font)
        img.save('/home/{}/artctrl/meme/galleries/{}/{}-{}.jpg'.format(myusr, user, memename, timstr))

        #img.save("/home/{}/memetest/galleries/{}/{}.jpg".format(myusr, usrfolz, gtm['id']))


    memedict = dict({'meme' : memename, 'toptext' : toptext.upper(), 'bottomtext' : bottomtext.upper(), 'imagepath' : '/home/{}/rbnz-tech-backup/artctrl/meme/galleries/{}/{}-{}.jpg'.format(myusr, user, memename, timstr)})
    return(jsonify(memedict))


if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(port=4321, host='0.0.0.0')
