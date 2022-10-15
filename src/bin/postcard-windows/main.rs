
use std::thread;

use native_windows_gui as nwg;
use native_windows_derive as nwd;

use nwd::NwgUi;
use nwg::NativeUi;
use tokio::runtime::Runtime;


#[derive(Default, NwgUi)]
pub struct BasicApp {
    #[nwg_control(size: (300, 280), position: (300, 300), title: "Basic example", flags: "WINDOW|VISIBLE")]
    #[nwg_events( OnWindowClose: [BasicApp::say_goodbye] )]
    window: nwg::Window,

    #[nwg_layout(parent: window, max_row: Some(5), spacing: 5)]
    layout: nwg::GridLayout,

    #[nwg_control(text: "Host:", h_align: HTextAlign::Right)]
    #[nwg_layout_item(layout: layout, col: 0, row: 0)]
    host_label: nwg::Label,

    #[nwg_control(text: "0.0.0.0:1080")]
    #[nwg_layout_item(layout: layout, col: 1, row: 0, col_span: 2)]
    host: nwg::TextInput,

    #[nwg_control(text: "Server:", h_align: HTextAlign::Right)]
    #[nwg_layout_item(layout: layout, col: 0, row: 1)]
    server_label: nwg::Label,

    #[nwg_control(text: "108.61.200.16")]
    #[nwg_layout_item(layout: layout, col: 1, row: 1, col_span: 2)]
    server: nwg::TextInput,

    #[nwg_control(text: "Private Key:", h_align: HTextAlign::Right)]
    #[nwg_layout_item(layout: layout, col: 0, row: 2)]
    private_key_label: nwg::Label,

    #[nwg_control(text: "CI6E1d1pyS0uvtzfcOvr2mHHnygponqXEiBEWeaf1X0=")]
    #[nwg_layout_item(layout: layout, col: 1, row: 2, col_span: 3)]
    private_key: nwg::TextInput,

    #[nwg_control(text: "Public Key:", h_align: HTextAlign::Right)]
    #[nwg_layout_item(layout: layout, col: 0, row: 3)]
    public_key_label: nwg::Label,

    #[nwg_control(text: "TeWqA5wxTEWYvCCXE0QmkDCjwngrbNoUgE4qiC55+00=")]
    #[nwg_layout_item(layout: layout, col: 1, row: 3, col_span: 3)]
    public_key: nwg::TextInput,

    #[nwg_control(text: "Start")]
    #[nwg_layout_item(layout: layout, col: 1, row: 4, col_span: 2)]
    #[nwg_events( OnButtonClick: [BasicApp::start_local_client] )]
    start_button: nwg::Button
}

impl BasicApp {
    fn start_local_client(&self) {
        nwg::modal_info_message(&self.window, "Hello", &format!("Hello {}", self.host.text()));


        std::thread::spawn(|| {
                // Create the runtime
             let rt  = Runtime::new().unwrap();
             rt.block_on(async {

             });
        });
        
    }
    
    fn say_goodbye(&self) {
        nwg::stop_thread_dispatch();
    }

}

fn main() {
    nwg::init().expect("Failed to init Native Windows GUI");
    nwg::Font::set_global_family("Segoe UI").expect("Failed to set default font");

    let _app = BasicApp::build_ui(Default::default()).expect("Failed to build UI");

    nwg::dispatch_thread_events();
}