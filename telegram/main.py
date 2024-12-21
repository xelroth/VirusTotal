from pyrogram import Client, filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
import os
import threading
import time
import botfunctions
from telegraph import Telegraph

class VirusTotalBot:
    MAX_FILE_SIZE = 681574400

    def __init__(self):
        self.bot_token = os.environ.get("TOKEN", "")
        self.api_hash = os.environ.get("HASH", "")
        self.api_id = os.environ.get("ID", "")
        self.app = Client("my_bot", api_id=self.api_id, api_hash=self.api_hash, bot_token=self.bot_token)
        self.telegraph = Telegraph()
        self.telegraph.create_account(short_name='VirusTotal')
        self.__setup_handlers__()

    def __setup_handlers__(self):
        self.app.on_message(filters.command(["start"]))(self.__start_command__)
        self.app.on_message(filters.document)(self.__document_handler__)
        self.app.on_callback_query()(self.__callback_handler__)

    def __start_command__(self, client, message):
        start_message = (f'👋🏻 Hello! {message.from_user.mention}\n'
                         'I am a Bot based on **[VT-SCRAP](https://github.com/Brijeshkrishna/virustotal-scrapper)**\n\n'
                         '__• You can send the file to the bot or forward it from another channel, and it will check the file to **[VirusTotal](http://virustotal.com/)** with over **70** different antiviruses.__\n\n'
                         '• To get scan results - send me any file up to **650 MB** in size, and you will receive a detailed analysis of it.\n\n'
                         '• With the help of a bot, you can analyze suspicious files to identify viruses and other bad programs.\n\n'
                         '• You can also add me to your chats, and I will be able to analyze the files sent by participants.__')

        self.app.send_message(message.chat.id, start_message, reply_to_message_id=message.id,
                              disable_web_page_preview=True,
                              reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("📦 Source Code", url="https://github.com/bipinkrish/VirusTotal-Bot")]]))

    def __document_handler__(self, client, message):
        if int(message.document.file_size) > self.MAX_FILE_SIZE:
            self.app.send_message(message.chat.id, "⭕️ File is too Big for VirusTotal. It should be less than 650 MB", reply_to_message_id=message.id)
            return
        threading.Thread(target=self.__check_virus__, args=(message,), daemon=True).start()

    def __check_virus__(self, message):
        msg = self.app.send_message(message.chat.id, '🔽 Downloading...', reply_to_message_id=message.id)
        print(f"Downloading: ID:  {message.id}  size: {message.document.file_size}")
        dnsta = threading.Thread(target=lambda: self.__downstatus__(f'{message.id}downstatus.txt', msg), daemon=True)
        dnsta.start()

        file = self.app.download_media(message, progress=self.__progress__, progress_args=[message])
        os.remove(f'{message.id}downstatus.txt')
        self.app.edit_message_text(message.chat.id, msg.id, '🔼 Uploading to VirusTotal...')
        print(f"Uploading: ID: {message.id}  size: {message.document.file_size}")

        hash_value = botfunctions.uploadfile(file)
        os.remove(file)
        print(f'ID: {message.id}  HASH: {hash_value}')
        
        if hash_value == 0:
            self.app.edit_message_text(message.chat.id, msg.id, "✖️ Failed")
            print("HASH is 0")
            return
            
        self.app.edit_message_text(message.chat.id, msg.id, '⚙️ Checking...')
        print(f"Checking: ID:  {message.id}  size: {message.document.file_size}")
        main_text, check_text, signatures, link = botfunctions.cleaninfo(hash_value)
        
        if main_text is None:
            self.app.edit_message_text(message.chat.id, msg.id, "✖️ Failed")
            print("Function returned None")
            return

        response = self.telegraph.create_page('VT', content=[f'{main_text}-|-{check_text}-|-{signatures}-|-{link}'])
        tlink = response['url']

        self.app.edit_message_text(message.chat.id, msg.id, main_text,
                                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🧪 Detections", callback_data=f"D|{tlink}"),
                                                                        InlineKeyboardButton("🌡 Signatures", callback_data=f"S|{tlink}")],
                                                                       [InlineKeyboardButton("🔗 View on VirusTotal", url=link)]]))

    def __downstatus__(self, statusfile, message):
        while True:
            if os.path.exists(statusfile):
                break  
        while os.path.exists(statusfile):
            with open(statusfile, "r") as upread:
                txt = upread.read()
            try:
                self.app.edit_message_text(message.chat.id, message.id, f"🔽 Downloaded... {txt}")
                time.sleep(10)
            except:
                time.sleep(5)

    def __progress__(self, current, total, message):
        with open(f'{message.id}downstatus.txt', "w") as file_up:
            file_up.write(f"{current * 100 / total:.1f}%")

    def __callback_handler__(self, client, message):
        url = message.message.reply_markup.inline_keyboard[1][0].url
        action, tlink = message.data.split("|")
        result = self.telegraph.get_page(tlink.split("https://telegra.ph/")[1], return_content=True, return_html=False)
        main_text, check_text, signatures = result["content"][0].split("-|-")

        if action == "B":
            self.app.edit_message_text(message.message.chat.id, message.message.id, main_text,
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🧪 Detections", callback_data=f"D|{tlink}"),
                                                                            InlineKeyboardButton("🌡 Signatures", callback_data=f"S|{tlink}")],
                                                                           [InlineKeyboardButton("🔗 View on VirusTotal", url=url)]]))

        elif action == "D":
            self.app.edit_message_text(message.message.chat.id, message.message.id, check_text,
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data=f"B|{tlink}"),
                                                                            InlineKeyboardButton("🌡 Signatures", callback_data=f"S|{tlink}")],
                                                                           [InlineKeyboardButton("🔗 View on VirusTotal", url=url)]]))

        elif action == "S":
            self.app.edit_message_text(message.message.chat.id, message.message.id, signatures,
                                        reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Back", callback_data=f"B|{tlink}"),
                                                                            InlineKeyboardButton("🧪 Detections", callback_data=f"D|{tlink}")],
                                                                           [InlineKeyboardButton("🔗 View on VirusTotal", url=url)]]))

    def run(self):
        self.app.run()

if __name__ == "__main__":
    bot = VirusTotalBot()
    bot.run()
