use std::cell::RefCell;
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::Duration;

use native_windows_derive as nwd;
use native_windows_gui as nwg;

use nwd::NwgUi;
use nwg::NativeUi;
use tokio::runtime::Runtime;
use tokio::select;

#[derive(Debug, PartialEq, Eq)]
enum Command {
    Stop,
}

enum Kind {
    ClientDone,
    ClientError,
}

struct Status {
    kind: Kind,
    msg: String,
}

impl Status {
    fn new(kind: Kind, msg: impl ToString) -> Self {
        Status {
            kind,
            msg: msg.to_string(),
        }
    }

    fn from_kind(kind: Kind) -> Self {
        Status::new(kind, "")
    }
}

#[derive(Default, NwgUi)]
pub struct BasicApp {
    #[nwg_control(size: (300, 280), position: (300, 300), title: "Postcard", flags: "WINDOW|VISIBLE")]
    #[nwg_events( OnInit: [BasicApp::setup], OnWindowClose: [BasicApp::say_goodbye] )]
    window: nwg::Window,

    #[nwg_layout(parent: window, max_row: Some(5), spacing: 5)]
    layout: nwg::GridLayout,

    #[nwg_control(text: "Host:", h_align: HTextAlign::Left)]
    #[nwg_layout_item(layout: layout, col: 0, row: 0)]
    host_label: nwg::Label,

    #[nwg_control(text: "127.0.0.1:1080")]
    #[nwg_layout_item(layout: layout, col: 1, row: 0, col_span: 2)]
    host: nwg::TextInput,

    #[nwg_control(text: "Server:", h_align: HTextAlign::Left)]
    #[nwg_layout_item(layout: layout, col: 0, row: 1)]
    server_label: nwg::Label,

    #[nwg_control(text: "108.61.200.16")]
    #[nwg_layout_item(layout: layout, col: 1, row: 1, col_span: 2)]
    server: nwg::TextInput,

    #[nwg_control(text: "Private Key:", h_align: HTextAlign::Left)]
    #[nwg_layout_item(layout: layout, col: 0, row: 2)]
    private_key_label: nwg::Label,

    #[nwg_control(text: "")]
    #[nwg_layout_item(layout: layout, col: 1, row: 2, col_span: 3)]
    private_key: nwg::TextInput,

    #[nwg_control(text: "Public Key:", h_align: HTextAlign::Left)]
    #[nwg_layout_item(layout: layout, col: 0, row: 3)]
    public_key_label: nwg::Label,

    #[nwg_control(text: "")]
    #[nwg_layout_item(layout: layout, col: 1, row: 3, col_span: 3)]
    public_key: nwg::TextInput,

    #[nwg_control(text: "Start")]
    #[nwg_layout_item(layout: layout, col: 1, row: 4)]
    #[nwg_events( OnButtonClick: [BasicApp::start_local_client] )]
    start_button: nwg::Button,

    #[nwg_control(text: "Stop")]
    #[nwg_layout_item(layout: layout, col: 3, row: 4)]
    #[nwg_events( OnButtonClick: [BasicApp::stop_local_client] )]
    stop_button: nwg::Button,

    #[nwg_control]
    #[nwg_events(OnNotice: [BasicApp::update_status])]
    update_status: nwg::Notice,

    cmd_sender: RefCell<Option<Sender<Command>>>,
    notice_receiver: RefCell<Option<Receiver<Status>>>,

    client_thread: RefCell<Option<thread::JoinHandle<()>>>,
}

impl BasicApp {
    fn setup(&self) {
        self.start_button.set_enabled(true);
        self.stop_button.set_enabled(false);
    }

    fn start_local_client(&self) {
        let (cmd_sender, cmd_receiver) = channel();
        let (status_sender, status_receiver) = channel();

        *self.cmd_sender.borrow_mut() = Some(cmd_sender);
        *self.notice_receiver.borrow_mut() = Some(status_receiver);

        let host = self.host.text();
        let server = self.server.text();
        let private_key = self.private_key.text();
        let public_key = self.public_key.text();

        self.start_button.set_enabled(false);
        self.stop_button.set_enabled(true);

        // Creates a sender to trigger the `OnNotice` event
        let notice_notifier = self.update_status.sender();

        let client_thread = std::thread::spawn(move || {
            // Create the runtime
            let rt = Runtime::new().unwrap();
            rt.block_on(async {
                let mut status = Status::from_kind(Kind::ClientDone);

                select! {
                    _ = wait_stop(cmd_receiver) => {
                    }

                    ret = postcard::client::start_client(&host, &server, &private_key, &public_key) => {
                        if let Err(err) = ret {
                            status = Status::new(Kind::ClientError, err);
                        };
                    }
                };

                status_sender.send(status).unwrap();

                notice_notifier.notice();
            });
        });

        *self.client_thread.borrow_mut() = Some(client_thread);
    }

    fn stop_local_client(&self) {
        self.cmd_sender
            .borrow_mut()
            .as_mut()
            .unwrap()
            .send(Command::Stop)
            .unwrap();
    }

    fn say_goodbye(&self) {
        nwg::stop_thread_dispatch();
    }

    fn update_status(&self) {
        let mut receiver_ref = self.notice_receiver.borrow_mut();
        let receiver = receiver_ref.as_mut().unwrap();
        while let Ok(status) = receiver.try_recv() {
            let Status { kind, msg } = status;
            match &kind {
                Kind::ClientDone => {
                    self.start_button.set_enabled(true);
                    self.stop_button.set_enabled(false);
                    *self.client_thread.borrow_mut() = None;
                }
                Kind::ClientError => {
                    println!("err: {:?}", &msg);

                    nwg::modal_info_message(
                        &self.window,
                        "Error",
                        &format!("start client failed, {}", msg),
                    );
                    self.start_button.set_enabled(true);
                    self.stop_button.set_enabled(false);
                    *self.client_thread.borrow_mut() = None;
                }
            }
        }
    }
}

async fn wait_stop(signal: Receiver<Command>) {
    loop {
        tokio::time::sleep(Duration::from_millis(200)).await;

        match signal.try_recv() {
            Ok(cmd) => {
                if cmd == Command::Stop {
                    return;
                }
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                println!("reciver disconnected");
                return;
            }
        }
    }
}

fn main() {
    nwg::init().expect("Failed to init Native Windows GUI");
    nwg::Font::set_global_family("Segoe UI").expect("Failed to set default font");

    let _app = BasicApp::build_ui(Default::default()).expect("Failed to build UI");

    nwg::dispatch_thread_events();
}
