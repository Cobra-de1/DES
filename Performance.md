
# Performance

## Hardware resources

    Processor: AMD Ryzen 7 3750H with Radeon Vega Mobile Gfx   (8 CPUs), ~2.3GHz
    Available OS Memory: 15810MB RAM
    OS: 
    +) Windows 10 Pro 64-bit (10.0, Build 19042) (19041.vb_release.191206-1406)
    +) Kali linux 2021.1 amd64

## Computation Performance

### Plaintext: 

Harry Potter và Hòn đá Phù thủy (tiếng Anh: Harry Potter and the Philosophers Stone) là tác phẩm đầu tiên trong bộ truyện Harry Potter gồm 7 tập của nữ văn sĩ người Anh J. K. Rowling. Quyển sách đã được xuất bản ngày 30 tháng 6 năm 1997 bởi nhà bản Bloomsbury. Đây là một tập truyện quan trọng, bởi nó đặt nền tảng cho 6 tập tiếp theo. Nó giúp ta bước đầu khám phá thế giới Pháp thuật của Harry Potter, làm quen với các nhân vật chính, địa điểm, với một số thuật ngữ... Tập đầu tiên này đưa ra những câu hỏi chưa có câu trả lời, bằng những dấu hiệu cho những tình tiết trong các tập tiếp theo, tạo cho độc giả sự tò mò.

### Run 1000 times and take the average (ms)

|Scheme|	Mode|	Key length|	IV length|	Encryption  (Windows)|	Decryption (Windows)|	Encryption (Linux)|	Decryption (Linux)|
|--|------|-------|------|------|------|------|------|
|DES|	ECB|	64|		|0.0121|	0.0121|	0.0163|	0.0111|
|DES|	CBC|	64|	64|	0.0139|	0.0123|	0.0177|	0.0113|
|DES|	CBC_CTS|	64|	64|	0.0140|	0.0124|	0.0177|	0.0114|
|DES|	OFB|	64|	64|	0.0134|	0.0132|	0.0174|	0.0120|
|DES|	CFB|	64|	64|	0.0131|	0.0122|	0.0173|	0.0114|
|DES|	CTR|	64|	64|	0.0132|	0.0129|	0.0176|	0.0122|
