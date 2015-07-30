import re
import json
import os
from functools import wraps
from threading import Event

from libmproxy.protocol.http import decoded

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


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
    backend = default_backend()
    key = AES_SECRET.decode("hex")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(cryptotext)
    plaintext = plaintext + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded = unpadder.update(plaintext)
    unpadded += unpadder.finalize()
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


def decrypt_flow(flow, **kwargs):
    target = kwargs.get('target')

    iv = flow.request.headers.get('payload-session')[0].decode('hex')
    cryptotext = getattr(flow, target).content
    decrypted = decrypt(iv, cryptotext)

    return decrypted


def decrypt_request(flow):
    return decrypt_flow(flow, target='request')


def decrypt_response(flow):
    return decrypt_flow(flow, target='response')


def cheat_game(context, flow):
    if 'davincigames' not in flow.request.host:
        return

    desired_request = 'playRound'

    try:
        game_state = json.loads(context.plugins.get_option_value('ruzzle', 'game_state'))
    except ValueError:
        game_state = {}

    try:
        decrypted = decrypt_request(flow)
        request_json = json.loads(decrypted)

        if desired_request in flow.request.get_path_components():
            if game_state.get(unicode(request_json[u'round']['gameId'])):
                print "cheating at known game... " + unicode(request_json[u'round']['gameId'])
                this_game = game_state.get(unicode(request_json[u'round']['gameId']))
                target_player = str(this_game['target_player'])

                # find all the words possible
                all_words = request_json.get(
                    u'round')['board']['words']
                # now we need to play a winning game
                wordcount, all_word_movestring = get_movestring(
                    request_json.get(u'round')['board']['board'], all_words)

                # play all the words
                request_json[u'round'][
                    'player' + target_player + 'Moves'] = all_word_movestring
                request_json[u'round']['wordsInRound'] = wordcount

                # now change the swipe distance to something believable
                request_json[u'round'][
                    'player' + target_player + 'SwipeDistance'] = int(len(all_word_movestring) / 0.09733124018838304)
                request_json[u'round']['swipeDistance'] = int(
                    len(all_word_movestring) / 0.09733124018838304)

                # now make a string of move times...
                # should probably randomize these so the bot isn't as
                # fingerprintable :)
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
                request_json[u'round'][
                    'player' + target_player + 'MoveTimes'] = moveTimes

                # now update our score
                request_json[u'round']['player' + target_player + 'Score'] = sum([score_word(request_json.get(
                    u'round')['board']['board'], request_json.get(u'round')['board']['bonus'], word) for word in all_words])

                # no errors!
                request_json[u'round']['moveErrors'] = 0
                request_json[u'round'][
                    'Player' + target_player + 'MoveErrors'] = 0

                # re-encrypt and put back on the wire
                iv = flow.request.headers.get('payload-session')[0].decode('hex')
                flow.request.content = encrypt(
                    iv, json.dumps(request_json))

    except Exception, e:
        print "Error cheating"
        print repr(e)


def extract_game(context, flow):
    try:
        try:
            game_state = json.loads(context.plugins.get_option_value('ruzzle', 'game_state'))
        except ValueError:
            game_state = {}

        with decoded(flow.request):
            if 'davincigames' not in flow.request.host:
                return

            if 'readGame' in flow.request.get_path_components():
                # we can extract the user ID for a game from this request
                # object
                request_json = json.loads(decrypt_request(flow))
                try:
                    game = game_state.get(unicode(request_json[u'game']['id'])) or {}
                    if request_json.get(u'game').get('player1User'):
                        # the first readGame request doesn't have all the game state
                        # but the response will
                        if int(request_json[u'game'].get('player1User').get('userId')) == int(MY_USER_ID):
                            game['target_player'] = 1
                        else:
                            game['target_player'] = 2

                        game['description'] = "Player 1: %s vs 2: %s" % (request_json[u'game'].get('player1User').get('userId'), request_json[u'game'].get('player2User').get('userId'))
                        game_state[unicode(request_json[u'game']['id'])] = game

                except Exception, e:
                    print("EXCEPTION")
                    print(repr(e))

            if flow.response:
                with decoded(flow.response):
                    # response available on this flow...
                    response_json = json.loads(decrypt_response(flow))
                    if response_json.get('game'):
                        # there's a game element present
                        server_game = response_json['game']
                        game = game_state.get(unicode(server_game['id'])) or {}
                        game['round'] = server_game.get('round')
                        game_state[unicode(server_game['id'])] = game

                    if response_json.get('player1User'):
                        # readGame response
                        if 'readGame' in flow.request.get_path_components():
                            if int(response_json.get('player1User').get('userId')) == int(MY_USER_ID):
                                game['target_player'] = 1
                            else:
                                game['target_player'] = 2

                            game['description'] = "Player 1: %s vs 2: %s" % (response_json.get('player1User').get('userId'), response_json.get('player2User').get('userId'))
                            game_state[unicode(response_json['id'])] = game

            context.plugins.set_option_value('ruzzle', 'game_state', json.dumps(game_state))
    except Exception, e:
        print "Error extracting game: %s" % repr(e)


def start(context, argv):
    context.plugins.register_view('Decrypt',
                                  title='Ruzzle Decrypt View Plugin',
                                  transformer=decrypt_flow)

    context.plugins.register_action('ruzzle',
                                    title='Ruzzle Cheats',
                                    actions=[
                                        {
                                          'title': 'Extract Game Info',
                                          'id': 'extract_game',
                                          'possible_hooks': [
                                                'request',
                                                'response', ],
                                          'state': {
                                              'every_flow': True,
                                          },
                                        },
                                        {
                                          'title': 'Cheat at Game',
                                          'id': 'cheat_game',
                                          'possible_hooks': [
                                                'request',
                                          ],
                                          'state': {
                                              'every_flow': False,
                                          },
                                        },
                                    ],
                                    options=[{
                                        'title': 'Game State',
                                        'id': 'game_state',
                                        'state': {
                                            'value': 'No Games Detected',
                                        },
                                        'type': 'display_only',
                                    }],
                                    )
