@csrf_exempt
def notify(request):
    signature = request.GET.get('signature', '')
    timestamp = request.GET.get('timestamp', '')
    nonce = request.GET.get('nonce', '')
    encrypt_type = request.GET.get('encrypt_type', 'raw')
    msg_signature = request.GET.get('msg_signature', '')

    if not weixin.check_signature(consts.APP_TOKEN, signature, timestamp, nonce):
        return HttpResponse(status=403)

    if request.method == 'GET':
        echo_str = request.GET.get('echostr', '')
        return HttpResponse(echo_str)

    if encrypt_type == 'raw':
        msg = weixin.parse_message(request.body)
        if msg.type == 'text':
            reply = command_reply(msg)
            if not reply:
                robot_reply = build_robot_reply(msg.source, msg.content)
                reply = weixin.create_reply(robot_reply, msg)
        elif msg.type == "event":
            if msg.event == "click":
                if msg.key == 'custom_service':
                    reply = weixin.create_reply(MP_CUSTOM_SERVICE_CLICK_REPLY, msg)
                elif msg.key == "lucky":
                    cache_media_id = cache.get(MP_QIAN_MEDIA_ID)
                    reply = weixin.ImageReply(message=msg)
                    reply.media_id = cache_media_id if cache_media_id else "LBQn0dA9XOpnth-KR136IF924aiwnoSQJ8zTkiVIrVE"
            elif msg.event == "subscribe":
                reply = weixin.create_reply(MP_ARTICLE_REPLY, msg)
            else:
                reply = weixin.create_reply("", msg)
        elif msg.type == "voice":
            if not msg.recognition:
                reply = weixin.create_reply("无法识别", msg)
            else:
                robot_reply = build_robot_reply(msg.source, msg.recognition)
                reply = weixin.create_reply(robot_reply, msg)
        else:
            reply = weixin.create_reply('', msg)

        return HttpResponse(reply.render())
