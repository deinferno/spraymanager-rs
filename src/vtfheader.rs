use std::{mem, intrinsics::transmute};
use std::os::raw::*;
use std::cmp::max;
use std::io::{Error,ErrorKind};

const VTF_SIG: [c_char;4] = [86,84,70,0]; // VTF\0

//https://developer.valvesoftware.com/wiki/Valve_Texture_Format
#[allow(non_snake_case)]
#[repr(C, packed)]
#[derive(Copy,Clone,Debug,Default)]
pub struct VtfHeader {
    signature: [c_char;4],
    _version: [c_uint;2],
    _headerSize: c_uint,
    width: c_ushort,
    height: c_ushort,
    _flags: c_uint,
    _frames: c_ushort,
    _firstFrame: c_ushort,
    _padding0: [c_char;4],
    _reflectivity: [c_float;3],
    _padding1: [c_char;4],
    _bumpmapScale: c_float,
    _highResImageFormat: c_uint,
    _mipmapCount: c_char,
    _lowResImageFormat: c_uint,
    lowResImageWidth: c_char,
    lowResImageHeight: c_char,
}

const VTF_HEADER_SIZE: usize = mem::size_of::<VtfHeader>();

impl VtfHeader {
    pub fn load<T: std::io::Read>(mut buf: T) -> Result<VtfHeader,Box<dyn std::error::Error>> {

        let vtfh: VtfHeader = {
            let mut h = [0u8; VTF_HEADER_SIZE];
    
            buf.read_exact(&mut h[..])?;
    
            unsafe { transmute(h) }
        };

        if vtfh.signature != VTF_SIG {
            return Err(Box::new(Error::new(ErrorKind::InvalidData,"Invalid vtf signature")));
        }

        Ok(vtfh)
    }

    pub fn width(&self) -> i32 {return max(self.width as i32,self.lowResImageWidth as i32)}
    pub fn height(&self) -> i32 {return max(self.height as i32,self.lowResImageHeight as i32)}
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use crate::vtfheader::VtfHeader;
    #[test]
    fn parse() {
        let file = File::open("test/spray.vtf").unwrap();

        let vtfheader = VtfHeader::load(file).unwrap();

        assert_eq!(vtfheader.width(), 256);
        assert_eq!(vtfheader.height(), 512);
        assert_eq!(&vtfheader.lowResImageWidth, &0);
        assert_eq!(&vtfheader.lowResImageHeight, &0);

    }

}