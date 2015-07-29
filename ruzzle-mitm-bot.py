import re
import json
from functools import wraps
from threading import Event

from libmproxy.protocol.http import decoded

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from flask import Flask
from flask import render_template
from flask import request as frequest

app = Flask("ruzzle-mitm-bot")

MY_USER_ID = '4650359378'
scoring = {
    'A': 1,
    'B': 4,
    'C': 4,
    'D': 2,
    'E': 1,
    'F': 4,
    'G': 3,
    'H': 4,
    'I': 1,
    'J': 10,
    'K': 5,
    'L': 1,
    'M': 3,
    'N': 1,
    'O': 1,
    'P': 4,
    'Q': 10,
    'R': 1,
    'S': 1,
    'T': 1,
    'U': 2,
    'V': 4,
    'W': 4,
    'X': 8,
    'Y': 4,
    'Z': 10
}
AES_SECRET = "398C7E2774E7A196AF30DFED78762328427E1F1EAD4C1F5D0D86CE44948E1CB0"


# NOTE: this still will return an HTTP response to someone who finds it
# you should use a firewall in addition if you wish to avoid giving an
# indication of an HTTP service
def private(fxn):
    @wraps(fxn)
    def __inner(*args, **kwargs):
        if frequest.environ.get('HTTP_X_REAL_IP', frequest.remote_addr) != '127.0.0.1':
            return render_template('404.html'), 400

        return fxn(*args, **kwargs)

    return __inner


@app.route('/games')
@private
def games():
    return render_template('index.html', state=repr(app.mitm_context.state.get('games')))


@app.route('/events.json')
@private
def events():
    with open('/Users/chrisczub/.mitmproxy/weblog', 'a+') as log:
        try:
            if not frequest.args.get('noBlock'):
                app.event.wait(30)

            if app.event.isSet():
                app.event.clear()

            return json.dumps({'requests': app.mitm_context.state.get('requests'),
                               'responses': app.mitm_context.state.get('responses'),
                               'cheat_enabled': app.mitm_context.state.get('cheat_enabled')})
        except Exception, e:
            log.write(repr(e))


@app.route('/')
@private
def index():
    with open('/Users/chrisczub/.mitmproxy/weblog', 'a+') as log:
        try:
            return render_template('index.html', requests=app.mitm_context.state.get('requests'),
                                   responses=app.mitm_context.state.get('responses'))
        except Exception, e:
            log.write(repr(e))


def get_word_indexes(board, word):
    indexes = [board.index(char) for char in word]
    return indexes


def score_word(board, bonus, word):
    moves = get_word_indexes(board, word)
    score = 0
    double = False
    triple = False
    for move in moves:
        if bonus[move] == 'D':
            score += scoring.get(board[move]) * 2
        elif bonus[move] == 'T':
            score += scoring.get(board[move]) * 3
        else:
            score += scoring.get(board[move])

        if bonus[move] == 'V':
            double = True
        elif bonus[move] == 'W':
            triple = True

    if double:
        score *= 2
    elif triple:
        score *= 3

    return score


def get_moves(board, word):
    v7 = ""
    v1 = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C',
          'D', 'E', 'F']
    indexes = get_word_indexes(board, word)
    v8 = indexes
    v7 += v1[len(v8) - 1]
    v0 = v8
    v4 = len(v0)
    v3 = 0
    while True:
        if v3 >= v4:
            break

        v7 += v1[v0[v3]]
        v3 += 1

    return v7


def get_movestring(board, wordlist):
    return (len(wordlist), "".
                           join([get_moves(board, word) for word in wordlist]))


def uniq(lst):
    last = object()
    for item in lst:
        if item == last:
            continue
        yield item
        last = item


def sort_and_deduplicate(l):
    return list(uniq(sorted(l, reverse=True)))


def decode_moves(encoded_moves):
    results = []
    if not encoded_moves:
        return results

    for char in encoded_moves:
        v2 = 0
        while v2 < len(encoded_moves):
            char = encoded_moves[v2]
            hexchar = ('0' + char).decode('hex')
            v3 = ord(hexchar) + 1
            v0 = v2 + v3
            v6 = []
            v5 = 0
            while v2 < v0:
                v6.append(ord(('0' + encoded_moves[v2 + 1]).decode('hex')))
                v5 += 1
                v2 += 1

            v2 += 1
            results.append(v6)

    return sort_and_deduplicate(results)


def letterize(board, decoded_moves):
    results = []
    for word in decoded_moves:
        wordletters = "".join([board[l] for l in word])
        results.append(wordletters)

    return results


def decrypt(iv, cryptotext):
    with open('/Users/chrisczub/.mitmproxy/log', 'a+') as log:
        log.write('decrypting cryptotext...\n')
        backend = default_backend()
        key = AES_SECRET.decode("hex")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(cryptotext)
        plaintext = plaintext + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(plaintext)
        unpadded += unpadder.finalize()
        log.write('decoding plaintext...\n')
        unpadded = unpadded.decode('utf-8')
        return unpadded


def encrypt(iv, plaintext):
    plaintext = plaintext.encode('utf-8')
    backend = default_backend()
    key = AES_SECRET.decode("hex")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext)
    padded_data += padder.finalize()
    cryptotext = decryptor.update(padded_data)
    cryptotext = cryptotext + decryptor.finalize()
    return cryptotext


def start_servers(context):
    with open('/Users/chrisczub/.mitmproxy/weblog', 'a+') as log:
        try:
            log.write("starting servers\n")
            # flask app
            # store a reference to the context on it
            app.mitm_context = context
        except Exception, e:
            log.write(repr(e))


def start(context, argv):
    with open('/Users/chrisczub/.mitmproxy/log', 'a+') as log:
        log.write("start")
        if len(argv) != 2:
            raise ValueError('Usage: -s "ruzzle-mitm-bot.py dirname"')
        context.dirname = argv[1]
        context.seen = {}
        context.state = {'games': {}, 'requests': [], 'responses': [], 'cheat_enabled': True}

        # store a reference to the context on it
        app.mitm_context = context
        context.app_registry.add(app, "ruzzle", 80)

        # create event for synchronization
        app.event = Event()
        context.event = app.event
        # first call should just return empty, subsequent will block
        app.event.set()


def get_filenames(context, flow, type):
    filename = flow.request.host + '_' + flow.request.path
    filename = filename.strip().replace(' ', '_')
    filename = re.sub(r'(?u)[^-\w.]', '_', filename)
    filename = filename + "." + type

    if not context.seen.get(filename):
        context.seen[filename] = 1
    else:
        context.seen[filename] = context.seen[filename] + 1

    filename = filename + "." + str(context.seen[filename])
    cryptofile = context.dirname + '/' + filename + ".crypto.bin"
    plainfile = context.dirname + '/' + filename + ".plain.bin"

    return (cryptofile, plainfile)


def get_desired_request(mode):
    desired_request = ''
    if mode == 'waiting_for_game':
        desired_request = 'createGame'
    elif mode == 'waiting_to_intercept':
        desired_request = 'playRound'
    return desired_request


def request(context, flow):
    with open("/Users/chrisczub/.mitmproxy/log", "a+") as log:
        if not 'davincigames' in flow.request.host:
            return

        if not context.state.get('mode') in ('waiting_for_game', 'waiting_to_intercept'):
            context.state['mode'] = 'waiting_for_game'

        desired_request = get_desired_request(context.state.get('mode'))

        try:
            cryptofile, plainfile = get_filenames(context, flow, "request")
            iv = flow.request.headers.get('payload-session')[0].decode('hex')
            cryptotext = flow.request.content
            decrypted = decrypt(iv, cryptotext)
            context.state['requests'].append({'body': decrypted,
                                              'url': "%s%s" % (flow.request.host, flow.request.path),
                                              'method': flow.request.method})
            context.request_json = json.loads(decrypted)

            if 'readGame' in flow.request.get_path_components():
                # we can extract the user ID for a game from this request object
                try:
                    if context.request_json[u'game'].get('player1User').get('userId') == int(MY_USER_ID):
                        context.state['games'][unicode(context.request_json[u'game']['id'])] = 1
                    else:
                        context.state['games'][unicode(context.request_json[u'game']['id'])] = 2
                except Exception, e:
                    log.write("EXCEPTION, setting player 2...")
                    log.write(repr(e))
                    context.state['games'][unicode(context.request_json[u'game']['id'])] = 2

            if context.cheat_enabled and desired_request in flow.request.get_path_components():
                if desired_request == 'playRound' and \
                        context.state['games'].get(unicode(context.request_json[u'round']['gameId'])):
                    player_id = str(context.state['games'].get(unicode(context.request_json[u'round']['gameId'])))
                    # find all the words possible
                    all_words = context.request_json.get(u'round')['board']['words']
                    context.state['mode'] = 'waiting_for_game'
                    # now we need to play a winning game
                    wordcount, all_word_movestring = get_movestring(context.request_json.get(u'round')['board']['board'], all_words)
                    log.write("Hacked word choices from\n")
                    log.write(repr(letterize(context.request_json.get(u'round')['board']['board'], decode_moves(context.request_json[u'round']['player' + player_id + 'Moves']))))
                    log.write("\n")
                    # play all the words
                    context.request_json[u'round']['player' + player_id + 'Moves'] = all_word_movestring
                    context.request_json[u'round']['wordsInRound'] = wordcount

                    # now change the swipe distance to something believable
                    context.request_json[u'round']['player' + player_id + 'SwipeDistance'] = int(len(all_word_movestring) / 0.09733124018838304)
                    context.request_json[u'round']['swipeDistance'] = int(len(all_word_movestring) / 0.09733124018838304)

                    # now make a string of move times...
                    # should probably randomize these so the bot isn't as fingerprintable :)
                    lastmovetime = 106600
                    firstmovetime = 8866
                    increment = (lastmovetime - firstmovetime) / wordcount
                    count = 1
                    moveTimes = str(firstmovetime)
                    prevmovetime = firstmovetime
                    while count < wordcount:
                        moveTimes += "," + str(prevmovetime + increment)
                        prevmovetime = prevmovetime + increment
                        count += 1
                    context.request_json[u'round']['player' + player_id + 'MoveTimes'] = moveTimes

                    # now update our score
                    context.request_json[u'round']['player' + player_id + 'Score'] = sum([score_word(context.request_json.get(u'round')['board']['board'], context.request_json.get(u'round')['board']['bonus'], word) for word in all_words])

                    # no errors!
                    context.request_json[u'round']['moveErrors'] = 0
                    context.request_json[u'round']['Player' + player_id + 'MoveErrors'] = 0
                    context.state['requests'].pop()
                    context.state['requests'].append({'body': json.dumps(context.request_json),
                                                      'url': "%s%s" % (flow.request.host, flow.request.path),
                                                      'method': flow.request.method})
                    flow.request.content = encrypt(iv, json.dumps(context.request_json))

            # tell the other threads we have new data
            context.event.set()

        except Exception, e:
            log.write("EXCEPTION DECRYPTING REQUEST!\n")
            log.write(repr(e))


def response(context, flow):
    with open("/Users/chrisczub/.mitmproxy/log", "a+") as log:
        if 'davincigames' not in flow.request.host:
            return

        desired_request = get_desired_request(context.state.get('mode'))
        try:
            log.write('response coming in...\n')
            with decoded(flow.response):  # automatically decode gzipped responses.
                cryptofile, plainfile = get_filenames(context, flow, "response")
                iv = flow.request.headers.get('payload-session')[0].decode('hex')
                cryptotext = flow.response.content

                log.write('decrypting response...\n')
                decrypted = decrypt(iv, cryptotext)
                context.state['responses'].append({'body': decrypted,
                                                   'url': "%s%s" % (flow.request.host, flow.request.path),
                                                   'method': flow.request.method})
                log.write('loading json...\n')
                context.response_json = json.loads(decrypted)
                log.write('decrypted...\n')

            if desired_request in flow.request.get_path_components():
                if desired_request == 'createGame':
                    context.state['mode'] = 'waiting_to_intercept'
                    # now we need to pull the user's ID from the game
                    # we could also do more things like verify the game ID
                    # against the one used in playRound, otherwise we might
                    # make some invalid requests
                    log.write('gonna f with it...\n')
                    try:
                        if context.response_json.get('player1User').get('userId') == MY_USER_ID:
                            context.state['games'][unicode(context.response_json.get('id'))] = 1
                        else:
                            context.state['games'][unicode(context.response_json.get('id'))] = 2
                    except Exception, e:
                        log.write("EXCEPTION, setting player 2...")
                        log.write(repr(e))
                        context.state['games'][unicode(context.response_json.get('id'))] = 2
            # tell the other threads we have new data
            context.event.set()
        except Exception, e:
            log.write("EXCEPTION DECRYPTING RESPONSE!\n")
            log.write(repr(e))
