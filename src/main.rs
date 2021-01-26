extern crate base64;
extern crate hex;

extern crate crypto;
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha2::Sha256;
use crypto::rc4::Rc4;
use crypto::symmetriccipher::{SynchronousStreamCipher};

use std::iter::repeat;
use std::{str, env};


//  reference:  https://github.com/HyperSine/how-does-Xmanager-encrypt-password/blob/master/doc/how-does-Xmanager-encrypt-password.md

// =================================================================================================
pub fn md5encode(input:&str) -> String {
    let mut mymd5 = Md5::new();
    mymd5.input_str(&input);
    return mymd5.result_str();
}

// =================================================================================================
pub fn sha256encode<S:Into<String>>(input: S) -> String {
    let mut sha256 = Sha256::new();
    sha256.input_str(&input.into());
    sha256.result_str()
}

// =================================================================================================
pub fn base64encode(input: &str) -> String {
    base64::encode(input)
}

pub fn base64decode(input: &str) -> String {
    let bytes = base64::decode(input).unwrap();
    return String::from_utf8_lossy(&bytes).to_string();
}

// =================================================================================================
pub fn hexencode(input:Vec<u8>) -> String {
    return hex::encode(input)
}

pub fn hexdecode(input:&str) -> Vec<u8> {
    let res = hex::decode(input).unwrap();
    // println!("{:?}",res);
    return res
}

// =================================================================================================
pub fn bytes_to_string(input:Vec<u8>) -> String {
    return String::from_utf8_lossy(&input).to_string()
}

pub fn string_to_bytes(input:String) -> Vec<u8> {
    return input.as_bytes().to_vec()
}

// =================================================================================================
pub fn rc4encrypt(key:Vec<u8>, input:&str) -> String {
    let mut rc4 = Rc4::new(&key);
    let mut result: Vec<u8> = repeat(0).take(input.len()).collect();
    rc4.process(input.as_bytes(), &mut result);
    return base64::encode(result)
}

pub fn rc4decrypt(key:Vec<u8>, input:&str) -> String {
    let mut rc4 = Rc4::new(&key);
    let data = base64::decode(input).unwrap();
    let mut result: Vec<u8> = repeat(0).take(data.len()).collect();
    rc4.process(&data, &mut result);
    return String::from_utf8_lossy(&result).to_string();
}

pub fn rc4encrypt_u8(key:Vec<u8>, input:&str) -> Vec<u8> {
    let mut rc4 = Rc4::new(&key);
    let mut result: Vec<u8> = repeat(0).take(input.len()).collect();
    rc4.process(input.as_bytes(), &mut result);
    return result;
}

pub fn rc4decrypt_u8(key:Vec<u8>, input:Vec<u8>) -> String {
    let mut rc4 = Rc4::new(&key);
    let data = input;
    let mut result: Vec<u8> = repeat(0).take(data.len()).collect();
    rc4.process(&data, &mut result);
    return String::from_utf8_lossy(&result).to_string();
}

pub fn rc4encrypt_str(key:&str,input: &str) -> String{
    let mut rc4 = Rc4::new(key.as_bytes());
    let mut result: Vec<u8> = repeat(0).take(input.len()).collect();
    rc4.process(input.as_bytes(), &mut result);
    return base64::encode(result);
}


pub fn rc4decrypt_str(key:&str,input: &str) -> String{
    let mut rc4 = Rc4::new(key.as_bytes());
    let data =base64::decode(input).unwrap();
    let mut result: Vec<u8> = repeat(0).take(data.len()).collect();
    rc4.process(&data, &mut result);
    return String::from_utf8_lossy(&result).to_string();
}

// =================================================================================================
// For session file version < 5.1 Encrypted by XShell
pub fn xa(input: &str) -> String {
    const XSHELLKEY: &str = "!X@s#h$e%l^l&";
    return rc4encrypt(hexdecode(&md5encode(XSHELLKEY)), &input);
    // return rc4decrypt(hexdecode(&md5encode(XSHELLKEY)),&input);
}
pub fn xa_(input: &str) -> String {
    const XSHELLKEY: &str = "!X@s#h$e%l^l&";
    // return rc4encrypt(hexdecode(&md5encode(XSHELLKEY)), &input);
    return rc4decrypt(hexdecode(&md5encode(XSHELLKEY)),&input);
}

// For session file version < 5.1 Encrypted by XFtp
pub fn xb(input: &str) -> String {
    const XFTPKEY: &str = "!X@s#c$e%l^l&";
    return rc4encrypt(hexdecode(&md5encode(XFTPKEY)),&input);
    // return rc4decrypt(hexdecode(&md5encode(XFTPKEY)),&input);
}
pub fn xb_(input: &str) -> String {
    const XFTPKEY: &str = "!X@s#c$e%l^l&";
    // return rc4encrypt(hexdecode(&md5encode(XFTPKEY)),&input);
    return rc4decrypt(hexdecode(&md5encode(XFTPKEY)),&input);
}


// For session file version == 5.1 OR 5.2
pub fn xc(sid: &str,input: &str) -> String  {
    let mut a=rc4encrypt_u8(hexdecode(&sha256encode(sid)),&input);
    let mut b=hexdecode(&sha256encode(input));
    a.append(&mut b);
    return base64::encode(a);
}
pub fn xc_(sid: &str,input: &str) -> String {
    let data=base64::decode(input).unwrap();
    let datalen=data.len()-32;
    return rc4decrypt_u8(hexdecode(&sha256encode(sid)), data[0..datalen].to_vec());
}

// For session file version > 5.2
pub fn xd(username: &str,sid: &str,input: &str) -> String  {
    let mut a=rc4encrypt_u8(hexdecode(&sha256encode(String::from(username)+&String::from(sid))),&input);
    let mut b=hexdecode(&sha256encode(input));
    a.append(&mut b);
    return base64::encode(a);
}
pub fn xd_(username: &str,sid: &str,input: &str) -> String {
    let data=base64::decode(input).unwrap();
    let datalen=data.len()-32;
    return rc4decrypt_u8(hexdecode(&sha256encode(String::from(username)+&String::from(sid))), data[0..datalen].to_vec());
}

// For session file version > 5.1 where user has set a master password
pub fn xe(password: &str,input: &str) -> String  {
    let mut a=rc4encrypt_u8(hexdecode(&sha256encode(password)),&input);
    let mut b=hexdecode(&sha256encode(input));
    a.append(&mut b);
    return base64::encode(a);
}
pub fn xe_(password: &str,input: &str) -> String {
    let data=base64::decode(input).unwrap();
    let datalen=data.len()-32;
    return rc4decrypt_u8(hexdecode(&sha256encode(password)), data[0..datalen].to_vec());
}

// =================================================================================================


fn main() {
    // /6KaTrKwm0cmhr0yAWQ=
    // TPKSg0QQ6o795vnPIMs=
    // hIMxIyQ3HbJsVIdbbunHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==
    // zv21O1x43qRs3c5NckDHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==
    // Rrm3P3AL0iDV7nBbS2bHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg==

    // const USERNAME: &str = "Administrator";
    // const SID: &str = "S-1-5-21-917267712-1342860078-1792151419-512";
    // const PASSWORD: &str = "123123";

    // println!("{}",xa("This is a test"));
    // println!("{}",xb("This is a test"));
    // println!("{}",xc(SID,"This is a test"));
    // println!("{}",xd(USERNAME,SID,"This is a test"));
    // println!("{}",xe(PASSWORD,"This is a test"));

    // println!("{}",xa_("/6KaTrKwm0cmhr0yAWQ="));
    // println!("{}",xb_("TPKSg0QQ6o795vnPIMs="));
    // println!("{}",xc_(SID,"hIMxIyQ3HbJsVIdbbunHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg=="));
    // println!("{}",xd_(USERNAME,SID,"zv21O1x43qRs3c5NckDHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg=="));
    // println!("{}",xe_(PASSWORD,"Rrm3P3AL0iDV7nBbS2bHvh7ZAvuN1NSJl8ZFL11+UJ+82+KAixa89O3OTAfRTg=="));

    let args: Vec<String> = env::args().collect();

    let banner=r"
    __  __    ___                           _
    \ \/ /   /   \___  ___ _ __ _   _ _ __ | |_
     \  /   / /\ / _ \/ __| '__| | | | '_ \| __|
     /  \  / /_//  __/ (__| |  | |_| | |_) | |_
    /_/\_\/___,' \___|\___|_|   \__, | .__/ \__|
                                |___/|_|
    ";


    let help ="
    # xa: For session file version < 5.1 .Encrypted by XShell
        usage: XDecrypt xa [CIPHERTEXT]

    # xb: For session file version < 5.1 .Encrypted by XFtp
        usage: XDecrypt xb [CIPHERTEXT]

    # xc: For session file version == 5.1 OR 5.2
        usage: XDecrypt xc [SID] [CIPHERTEXT]

    # xd: For session file version > 5.2
        usage: XDecrypt xd [USERNAME] [SID] [CIPHERTEXT]

    # xe: For session file version > 5.1 where user has set a master password
        usage: XDecrypt xe [PASSWORD] [CIPHERTEXT]
    ";
    println!("{}",banner);

    if args.len()>2{
        if args[1]=="-h" {
            println!("{}",help)
        }
        else if  args[1]=="xa"{
            println!("\tCLEADTEXT:\t{}",xa_(&args[2]));
        }
        else if  args[1]=="xb"{
            println!("\tCLEADTEXT:\t{}",xb_(&args[2]));
        }
        else if  args[1]=="xc"{
            println!("\tCLEADTEXT:\t{}",xc_(&args[2],&args[3]));
        }
        else if  args[1]=="xd"{
            println!("\tCLEADTEXT:\t{}",xd_(&args[2],&args[3],&args[4]));
        }
        else if  args[1]=="xe"{
            println!("\tCLEADTEXT:\t{}",xe_(&args[2],&args[3]));
        }
        else {
            println!("{}",help)
        }
    }
    else {
        println!("{}",help)
    }
}
