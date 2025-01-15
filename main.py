import tkinter as tk
from PIL import Image, ImageTk
from tkinter.filedialog import askopenfilename
import device_identifier as funcs
import os

root = tk.Tk()
root.title("IoT Device Identifier")
root.geometry("800x600")

# 加载并显示背景图片
image = Image.open("123.png")
im = ImageTk.PhotoImage(image)
image_label = tk.Label(root, image=im)
image_label.place(x=0, y=0, relwidth=1, relheight=1)


def upload_file(label):
    label.config(text="")
    for i in range(0, 27):
        canvas.itemconfig(lights[i], outline="black", fill='grey')
        canvas.itemconfig(texts[i], fill='grey')
    filetypes = (
        ('text files', '*.txt'),
        ('packet files', '*.pcap'),
        ('All files', '*.*')
    )

    filename = askopenfilename(
        title='Open a file',
        initialdir='/',
        filetypes=filetypes)

    # result = ""

    if filename:
        label.config(text="Identifying...")
        print(f"Selected file: {filename}")
        # 获取当前脚本所在的目录
        current_dir = os.path.dirname(os.path.abspath('main.py'))
        # 获取文件相对于当前脚本所在目录的相对路径
        relative_path = os.path.relpath(filename, current_dir)
        print(f"relative path: {relative_path}")
        num = -1
        while num == -1:
            num = funcs.device_classify(relative_path)

        result = funcs.types[num]
        canvas.itemconfig(lights[num], outline="black", fill='red')
        canvas.itemconfig(texts[num], fill='white')
        label.config(text=result)


# 创建按钮
def clear_result(label):
    label.config(text="")
    for i in range(0, 27):
        canvas.itemconfig(lights[i], outline="black", fill='grey')
        canvas.itemconfig(texts[i], fill='grey')


# 创建一个标签，用于显示文本
label = tk.Label(root, text="", bg = "black", height=3, width=20, foreground="white", font="Menlo")
# 设置标签的位置
label.place(x=580, y=510)

'''
# 创建一个标签，用于显示文本
label_result = tk.Label(root, text="Result:", height=3, width=10)
# 设置标签的位置
label_result.place(x=450, y=510)
'''


upload_button = tk.Button(root, text='Upload File', command=lambda: upload_file(label))
upload_button.place(x=60, y=520, width=100, height=40)

clear_button = tk.Button(root, text='Clear', command=lambda: clear_result(label))
clear_button.place(x=180, y=520, width=100, height=40)

canvas = tk.Canvas(root, width=700, height=460, bg='#323232')
canvas.place(x=50, y=25)

# 左上角坐标，右下角坐标 x1, y1, x2, y2
lights = []
texts = []
for i in range(0,9):
    light = canvas.create_oval(20, 40 - 10 + 50 * i, 30, 50 - 10 + 50 * i, outline="black", fill="grey")
    text = canvas.create_text(50, 45 - 10 + 50 * i, text=funcs.types[i], anchor='w', fill='grey')
    lights.append(light)
    texts.append(text)

for i in range(9,18):
    light = canvas.create_oval(270, 40 - 10 + 50 * i - 450, 280, 50 - 10 + 50 * i - 450, outline="black", fill="grey")
    text = canvas.create_text(300, 45 - 10 + 50 * i - 450, text=funcs.types[i], anchor='w', fill='grey')
    lights.append(light)
    texts.append(text)

for i in range(18,27):
    light = canvas.create_oval(520, 40 - 10 + 50 * i - 900, 530, 50 - 10 + 50 * i - 900, outline="black", fill="grey")
    text = canvas.create_text(550, 45 - 10 + 50 * i - 900, text=funcs.types[i], anchor='w', fill='grey')
    lights.append(light)
    texts.append(text)
root.mainloop()
