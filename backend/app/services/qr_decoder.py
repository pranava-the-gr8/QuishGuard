import cv2


def decode_qr(image_path: str) -> str:
    """
    Decode a QR code from an image.
    Returns the QR content as a string.
    Does not open or visit any URL.
    """

    image = cv2.imread(image_path)

    if image is None:
        raise ValueError("Unable to read the QR image")

    detector = cv2.QRCodeDetector()

    data, points, _ = detector.detectAndDecode(image)

    if not data:
        raise ValueError("No QR code could be decoded from the image")

    return data.strip()
