use std::{
    future::{self, Future},
    task::Poll,
};

pub struct RoundRobinSelector {
    a_first: bool,
}

impl RoundRobinSelector {
    pub fn new() -> RoundRobinSelector {
        RoundRobinSelector { a_first: true }
    }

    pub fn select<T>(
        &mut self,
        a: impl Future<Output = T>,
        b: impl Future<Output = T>,
    ) -> impl Future<Output = T> {
        let (mut a, mut b) = (Box::pin(a), Box::pin(b));
        let a_first = self.a_first;
        self.a_first = !self.a_first;
        future::poll_fn(move |cx| {
            if a_first {
                if let Poll::Ready(r) = a.as_mut().poll(cx) {
                    Poll::Ready(r)
                } else if let Poll::Ready(r) = b.as_mut().poll(cx) {
                    Poll::Ready(r)
                } else {
                    Poll::Pending
                }
            } else if let Poll::Ready(r) = b.as_mut().poll(cx) {
                Poll::Ready(r)
            } else if let Poll::Ready(r) = a.as_mut().poll(cx) {
                Poll::Ready(r)
            } else {
                Poll::Pending
            }
        })
    }
}
