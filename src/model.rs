use crate::Result;
use serde::{Serialize,Deserialize};
use std::{collections::BTreeMap, fmt, str::FromStr};

#[derive(Clone,Copy,Debug,Eq,PartialEq,Ord,PartialOrd)]
pub enum Core { Singbox, Xray }
impl Core {
    pub fn as_str(self)-> &'static str {match self{Self::Singbox=>"singbox",Self::Xray=>"xray"}}
    pub fn binary(self)-> &'static str {match self{Self::Singbox=>"sing-box",Self::Xray=>"xray"}}
    pub fn service(self)-> &'static str {match self{Self::Singbox=>"onebox-sing-box",Self::Xray=>"onebox-xray"}}
}
impl FromStr for Core {type Err=crate::Error;fn from_str(s:&str)->Result<Self>{match s{"singbox"|"sing-box"=>Ok(Self::Singbox),"xray"=>Ok(Self::Xray),_=>Err(format!("未知内核: {s}").into())}}}
impl fmt::Display for Core {fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str(self.as_str())}}

#[derive(Clone,Copy,Debug,Eq,PartialEq,Ord,PartialOrd)]
pub enum Protocol { VlessReality,VlessXhttp,VlessGrpc,VlessWs,VmessWs,Trojan,Shadowsocks,Hysteria2,Tuic,Anytls,Shadowtls,AnytlsReality }
pub const PROTOCOLS:[Protocol;12]=[Protocol::VlessReality,Protocol::VlessXhttp,Protocol::VlessGrpc,Protocol::VlessWs,Protocol::VmessWs,Protocol::Trojan,Protocol::Shadowsocks,Protocol::Hysteria2,Protocol::Tuic,Protocol::Anytls,Protocol::Shadowtls,Protocol::AnytlsReality];
impl Protocol {
    pub fn as_str(self)-> &'static str {match self{Self::VlessReality=>"vless-reality",Self::VlessXhttp=>"vless-xhttp",Self::VlessGrpc=>"vless-grpc",Self::VlessWs=>"vless-ws",Self::VmessWs=>"vmess-ws",Self::Trojan=>"trojan",Self::Shadowsocks=>"shadowsocks",Self::Hysteria2=>"hysteria2",Self::Tuic=>"tuic",Self::Anytls=>"anytls",Self::Shadowtls=>"shadowtls",Self::AnytlsReality=>"anytls-reality"}}
    pub fn title(self)-> &'static str {match self{Self::VlessReality=>"VLESS-Reality-Vision",Self::VlessXhttp=>"VLESS-XHTTP-Reality",Self::VlessGrpc=>"VLESS-gRPC-Reality",Self::VlessWs=>"VLESS-WS-TLS",Self::VmessWs=>"VMess-WS",Self::Trojan=>"Trojan-TLS",Self::Shadowsocks=>"Shadowsocks-2022",Self::Hysteria2=>"Hysteria2",Self::Tuic=>"TUIC-v5",Self::Anytls=>"AnyTLS",Self::Shadowtls=>"ShadowTLS-v3",Self::AnytlsReality=>"AnyTLS-REALITY"}}
    pub fn cores(self)-> &'static [Core] {match self{Self::VlessXhttp=>&[Core::Xray],Self::Tuic|Self::Anytls|Self::Shadowtls|Self::AnytlsReality=>&[Core::Singbox],_=>&[Core::Singbox,Core::Xray]}}
    pub fn reality(self)->bool {matches!(self,Self::VlessReality|Self::VlessXhttp|Self::VlessGrpc|Self::AnytlsReality)}
    pub fn certificate(self)->bool {matches!(self,Self::VlessWs|Self::Trojan|Self::Hysteria2|Self::Tuic|Self::Anytls)}
    pub fn network(self)-> &'static str {match self{Self::Hysteria2|Self::Tuic=>"udp",Self::Shadowsocks=>"both",_=>"tcp"}}
    pub fn supports(self,client:&str)->bool{match client{"singbox"|"sing-box"|"singbox-notun"|"sing-box-notun"=>self!=Self::VlessXhttp,"xray"=>!matches!(self,Self::Tuic|Self::Anytls|Self::AnytlsReality|Self::Shadowtls),"mihomo"|"clash"|"provider"=>self!=Self::AnytlsReality,"link"|"links"|"base64"|"sub"=>!matches!(self,Self::AnytlsReality|Self::Shadowtls),_=>false}}
}
impl FromStr for Protocol{type Err=crate::Error;fn from_str(s:&str)->Result<Self>{PROTOCOLS.into_iter().find(|p|p.as_str()==s).ok_or_else(||format!("未知协议: {s}").into())}}
impl fmt::Display for Protocol{fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{f.write_str(self.as_str())}}

/// String values preserve the exact credentials and semantics of the v1 state.
#[derive(Clone,Debug,Default,Serialize,Deserialize,PartialEq,Eq)]
pub struct State {#[serde(default)] pub values:BTreeMap<String,String>}
impl State {
    pub fn get(&self,key:&str)->&str{self.values.get(key).map(String::as_str).unwrap_or("")}
    pub fn set(&mut self,key:&str,value:impl ToString){self.values.insert(key.into(),value.to_string());}
    pub fn flag(&self,key:&str)->bool{self.get(key)=="1"}
    pub fn get_or<'a>(&'a self,key:&str,default:&'a str)->&'a str{let v=self.get(key);if v.is_empty(){default}else{v}}
    pub fn number(&self,key:&str,default:u16)->u16{self.get(key).parse().unwrap_or(default)}
    pub fn protocols(&self)->Vec<Protocol>{self.get("PROTOCOLS").split_whitespace().filter_map(|s|s.parse().ok()).collect()}
    pub fn enabled(&self,p:Protocol)->bool{self.protocols().contains(&p)}
    pub fn port(&self,p:Protocol)->u16{self.number(&format!("PORT_{}",p.as_str().replace('-',"_")),443)}
    pub fn set_port(&mut self,p:Protocol,port:u16){self.set(&format!("PORT_{}",p.as_str().replace('-',"_")),port);}
    pub fn core(&self,p:Protocol)->Core{self.get(&format!("CORE_{}",p.as_str().replace('-',"_"))).parse().unwrap_or(p.cores()[0])}
    pub fn set_core(&mut self,p:Protocol,core:Core){self.set(&format!("CORE_{}",p.as_str().replace('-',"_")),core.as_str());}
    pub fn uses(&self,core:Core)->bool{self.protocols().iter().any(|p|self.core(*p)==core)}
    pub fn any_reality(&self)->bool{self.protocols().iter().any(|p|p.reality())}
    pub fn needs_cert(&self)->bool{self.protocols().iter().any(|p|p.certificate()||(*p==Protocol::VmessWs&&self.vmess_tls()))}
    pub fn vmess_tls(&self)->bool{self.flag("VMESS_TLS")||(self.get("VMESS_TLS").is_empty()&&matches!(self.get("TLS_MODE"),"acme"|"custom"))}
    pub fn node_name(&self,p:Protocol)->String{format!("{}-{}",self.get_or("NODE_NAME","onebox"),p.title())}
    pub fn site_enabled(&self)->bool{self.flag("REALITY_SITE_ENABLED")&&self.any_reality()}
    pub fn validate(&self)->Result<()> {
        let mut protocols=Vec::new();
        for name in self.get("PROTOCOLS").split_whitespace(){let p:Protocol=name.parse()?;if protocols.contains(&p){return Err("协议重复".into())}protocols.push(p);}
        if protocols.is_empty(){return Err("状态缺少协议列表".into())}
        for p in protocols {let raw=self.get(&format!("PORT_{}",p.as_str().replace('-',"_")));if raw.parse::<u16>().ok().filter(|v|*v>0).is_none(){return Err(format!("{p} 端口无效").into())}if !p.cores().contains(&self.core(p)){return Err(format!("{p} 不支持 {}",self.core(p)).into())}}
        Ok(())
    }
}

