use std::collections::HashSet;

use image::GrayImage;
use rxing::{BarcodeFormat, DecodeHints};

pub fn decode_luma(img: &GrayImage) -> Vec<String> {
    let mut hints = DecodeHints {
        PossibleFormats: Some(HashSet::from([BarcodeFormat::QR_CODE])),
        ..DecodeHints::default()
    };
    rxing::helpers::detect_multiple_in_luma_with_hints(
        img.as_raw().clone(),
        img.width(),
        img.height(),
        &mut hints,
    )
    .map(|found| found.into_iter().map(|r| r.getText().to_string()).collect())
    .unwrap_or_default()
}

pub fn decode_image_bytes(bytes: &[u8]) -> Result<Vec<String>, String> {
    let img = image::load_from_memory(bytes).map_err(|e| e.to_string())?;
    let found = decode_luma(&img.to_luma8());
    if found.is_empty() {
        Err("No QR code found in image".to_string())
    } else {
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageFormat, Luma};
    use std::io::Cursor;

    const URI: &str = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP";

    fn qr_image(data: &str) -> GrayImage {
        qrcode::QrCode::new(data.as_bytes())
            .unwrap()
            .render::<Luma<u8>>()
            .module_dimensions(4, 4)
            .build()
    }

    fn png(img: &GrayImage) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        img.write_to(&mut buf, ImageFormat::Png).unwrap();
        buf.into_inner()
    }

    #[test]
    fn decodes_png() {
        let bytes = png(&qr_image(URI));
        assert_eq!(decode_image_bytes(&bytes).unwrap(), vec![URI.to_string()]);
    }

    #[test]
    fn decodes_small_qr_in_large_image() {
        let qr = qr_image(URI);
        let mut big = GrayImage::from_pixel(1600, 1200, Luma([255u8]));
        image::imageops::overlay(&mut big, &qr, 700, 500);
        assert_eq!(decode_image_bytes(&png(&big)).unwrap(), vec![URI.to_string()]);
    }

    /// Google's export QR codes are dense (up to version 28). Every common
    /// screen width must decode, not just some of them.
    #[test]
    fn decodes_dense_qr_at_any_size() {
        let uri = format!("otpauth-migration://offline?data={}", "Q".repeat(1100));
        let qr = qr_image(&uri);
        let mut screen = GrayImage::from_pixel(qr.width() + 200, qr.height() * 2, Luma([255u8]));
        image::imageops::overlay(&mut screen, &qr, 100, i64::from(qr.height() / 2));
        for width in [480u32, 540, 640, 720, 800, 900, 1080, 1440] {
            let height = screen.height() * width / screen.width();
            let scaled =
                image::imageops::resize(&screen, width, height, image::imageops::FilterType::Triangle);
            assert_eq!(decode_luma(&scaled), vec![uri.clone()], "width {width}");
        }
    }

    #[test]
    fn no_qr() {
        let blank = GrayImage::from_pixel(200, 200, Luma([255u8]));
        assert_eq!(
            decode_image_bytes(&png(&blank)),
            Err("No QR code found in image".to_string())
        );
    }

    #[test]
    fn not_an_image() {
        assert!(decode_image_bytes(b"abc").is_err());
    }
}
