use image::GrayImage;

pub fn decode_luma(img: &GrayImage) -> Vec<String> {
    let mut prepared = rqrr::PreparedImage::prepare(img.clone());
    prepared
        .detect_grids()
        .into_iter()
        .filter_map(|grid| grid.decode().ok().map(|(_, content)| content))
        .collect()
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
