use crate::qr;
use image::codecs::jpeg::JpegEncoder;
use image::{GrayImage, RgbImage, imageops};
use nokhwa::Camera;
use nokhwa::pixel_format::RgbFormat;
use nokhwa::utils::{ApiBackend, CameraIndex, RequestedFormat, RequestedFormatType, Resolution};
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const NOT_AVAILABLE: &str = "Camera not available";

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct CameraInfo {
    pub index: u32,
    pub name: String,
}

pub struct Frame {
    /// At most PREVIEW_MAX_WIDTH pixels wide.
    pub preview_jpeg: Vec<u8>,
    pub decoded: Vec<String>,
}

const DECODE_MAX_SIDE: u32 = 1280;
const PREVIEW_MAX_WIDTH: u32 = 480;
const PREVIEW_QUALITY: u8 = 70;
/// About 5 decoded frames per second.
const FRAME_INTERVAL: Duration = Duration::from_millis(200);

/// Shrinks `img` so its long side is at most `max_side`, keeping the aspect ratio.
fn fit_long_side(img: &GrayImage, max_side: u32) -> GrayImage {
    let (w, h) = img.dimensions();
    let long = w.max(h);
    if long <= max_side {
        return img.clone();
    }
    imageops::thumbnail(img, w * max_side / long, h * max_side / long)
}

fn preview_jpeg(img: &RgbImage) -> Vec<u8> {
    let (w, h) = img.dimensions();
    let mut out = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut out, PREVIEW_QUALITY);
    let result = if w > PREVIEW_MAX_WIDTH {
        encoder.encode_image(&imageops::thumbnail(img, PREVIEW_MAX_WIDTH, h * PREVIEW_MAX_WIDTH / w))
    } else {
        encoder.encode_image(img)
    };
    if result.is_err() {
        out.clear();
    }
    out
}

/// Decodes QR codes and builds the preview for one camera frame.
fn process_frame(rgb: &RgbImage) -> Frame {
    let gray = image::DynamicImage::ImageRgb8(rgb.clone()).to_luma8();
    Frame {
        preview_jpeg: preview_jpeg(rgb),
        decoded: qr::decode_luma(&fit_long_side(&gray, DECODE_MAX_SIDE)),
    }
}

/// macOS asks for camera permission here; it blocks until the user answers.
fn init() {
    #[cfg(target_os = "macos")]
    {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            let (tx, rx) = mpsc::channel();
            nokhwa::nokhwa_initialize(move |ok| {
                let _ = tx.send(ok);
            });
            let _ = rx.recv();
        });
    }
}

pub fn list_cameras() -> Result<Vec<CameraInfo>, String> {
    init();
    let cameras = nokhwa::query(ApiBackend::Auto).map_err(|_| NOT_AVAILABLE)?;
    let mut list: Vec<CameraInfo> = cameras
        .into_iter()
        .filter_map(|c| {
            Some(CameraInfo {
                index: c.index().as_index().ok()?,
                name: c.human_name(),
            })
        })
        .collect();
    list.sort_by_key(|c| c.index);
    Ok(list)
}

fn open(index: u32) -> Result<Camera, String> {
    let want = |kind| RequestedFormat::new::<RgbFormat>(kind);
    let mut camera = Camera::new(
        CameraIndex::Index(index),
        want(RequestedFormatType::HighestResolution(Resolution::new(1280, 720))),
    )
    .or_else(|_| Camera::new(CameraIndex::Index(index), want(RequestedFormatType::AbsoluteHighestResolution)))
    .map_err(|_| NOT_AVAILABLE)?;
    camera.open_stream().map_err(|_| NOT_AVAILABLE)?;
    Ok(camera)
}

/// A running camera stream. Stopping or dropping it ends the capture thread.
pub struct CameraHandle {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl CameraHandle {
    pub fn stop(self) {}
}

impl Drop for CameraHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take()
            && thread.thread().id() != std::thread::current().id()
        {
            let _ = thread.join();
        }
    }
}

/// Opens camera `index` and calls `on_frame` about 5 times a second on its own thread.
/// A camera error ends the stream after one `Err` call.
pub fn start(
    index: u32,
    on_frame: impl Fn(Result<Frame, String>) + Send + 'static,
) -> Result<CameraHandle, String> {
    init();
    let stop = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = mpsc::channel();
    let stopped = stop.clone();
    let thread = std::thread::spawn(move || {
        // The camera is opened on this thread: some backends are not Send.
        let mut camera = match open(index) {
            Ok(c) => {
                let _ = ready_tx.send(Ok(()));
                c
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e));
                return;
            }
        };
        while !stopped.load(Ordering::Relaxed) {
            let began = Instant::now();
            let rgb = camera
                .frame()
                .and_then(|buffer| buffer.decode_image::<RgbFormat>())
                .map_err(|_| NOT_AVAILABLE.to_string());
            if stopped.load(Ordering::Relaxed) {
                break;
            }
            match rgb {
                Ok(rgb) => on_frame(Ok(process_frame(&rgb))),
                Err(e) => {
                    on_frame(Err(e));
                    break;
                }
            }
            std::thread::sleep(FRAME_INTERVAL.saturating_sub(began.elapsed()));
        }
        let _ = camera.stop_stream();
    });
    ready_rx.recv().map_err(|_| NOT_AVAILABLE.to_string())??;
    Ok(CameraHandle { stop, thread: Some(thread) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Luma, Rgb};

    const URI: &str = "otpauth://totp/Test:me?secret=JBSWY3DPEHPK3PXP&issuer=Test";

    #[test]
    fn large_frame_is_downscaled_to_long_side() {
        let out = fit_long_side(&GrayImage::new(1920, 1080), 1280);
        assert_eq!(out.dimensions(), (1280, 720));
        let out = fit_long_side(&GrayImage::new(1080, 1920), 1280);
        assert_eq!(out.dimensions(), (720, 1280));
    }

    #[test]
    fn small_frame_is_unchanged() {
        let out = fit_long_side(&GrayImage::new(640, 480), 1280);
        assert_eq!(out.dimensions(), (640, 480));
    }

    #[test]
    fn preview_is_at_most_480_wide_jpeg() {
        let jpeg = preview_jpeg(&RgbImage::new(1920, 1080));
        let img = image::load_from_memory(&jpeg).unwrap();
        assert_eq!(img.width(), 480);
        assert_eq!(img.height(), 270);
        assert_eq!(&jpeg[..2], &[0xFF, 0xD8]);
        let small = image::load_from_memory(&preview_jpeg(&RgbImage::new(320, 240))).unwrap();
        assert_eq!(small.width(), 320);
    }

    #[test]
    fn frame_with_qr_in_full_hd_decodes() {
        let qr = qrcode::QrCode::new(URI.as_bytes())
            .unwrap()
            .render::<Luma<u8>>()
            .module_dimensions(8, 8)
            .build();
        let mut rgb = RgbImage::from_pixel(1920, 1080, Rgb([255, 255, 255]));
        for (x, y, p) in qr.enumerate_pixels() {
            rgb.put_pixel(x + 600, y + 200, Rgb([p.0[0]; 3]));
        }
        let frame = process_frame(&rgb);
        assert_eq!(frame.decoded, vec![URI.to_string()]);
        assert!(!frame.preview_jpeg.is_empty());
    }

    #[test]
    fn frame_without_qr_decodes_nothing() {
        let frame = process_frame(&RgbImage::from_pixel(640, 480, Rgb([255, 255, 255])));
        assert!(frame.decoded.is_empty());
    }
}
