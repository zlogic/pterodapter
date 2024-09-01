use std::{
    future::{self, Future},
    task::Poll,
};

pub fn select<T>(
    a: impl Future<Output = T>,
    b: impl Future<Output = T>,
) -> impl Future<Output = T> {
    let (mut a, mut b) = (Box::pin(a), Box::pin(b));
    future::poll_fn(move |cx| {
        if let Poll::Ready(r) = a.as_mut().poll(cx) {
            Poll::Ready(r)
        } else if let Poll::Ready(r) = b.as_mut().poll(cx) {
            Poll::Ready(r)
        } else {
            Poll::Pending
        }
    })
}
