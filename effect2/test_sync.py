import attr
import pytest

from . import Effect, sync_perform, TypeDispatcher


class TestSynPerform:

    def test_perform_effect(self):
        @attr.s
        class EDoSomething:
            arg = attr.ib()

        dispatcher = TypeDispatcher({
            EDoSomething: lambda intent: 'bar'
        })
        effect = Effect(EDoSomething('foo'))
        ret = sync_perform(dispatcher, effect)
        assert ret == 'bar'

    def test_perform_coroutine(self):
        @attr.s
        class EDo:
            arg = attr.ib()

        async def do_func(a, b):
            done_a = await Effect(EDo(a))
            done_b = await Effect(EDo(b))
            return [done_a, done_b]

        coro = do_func(1, 2)
        dispatcher = TypeDispatcher({
            EDo: lambda intent: 'done: %s' % intent.arg
        })
        ret = sync_perform(dispatcher, coro)
        assert ret == ['done: 1', 'done: 2']

    def test_perform_not_an_effect(self):
        @attr.s
        class EDoSomething:
            pass

        dispatcher = TypeDispatcher({
            EDoSomething: lambda intent: 'bar'
        })
        with pytest.raises(AssertionError) as exc:
            sync_perform(dispatcher, EDoSomething())
        assert exc.value.args[0] == ('effect should be either an `Effect`'
                                     ' or a coroutine awaiting `Effect`s')

    def test_perform_coroutine_dont_await_effect(self):
        class NotAnEffect:
            def __await__(self):
                return (yield self)

        async def bad_do():
            await NotAnEffect()

        dispatcher = TypeDispatcher({
        })
        with pytest.raises(AssertionError) as exc:
            sync_perform(dispatcher, bad_do())
        assert exc.value.args[0].startswith('`sync_perform` can only await `Effect` (awaited:')

    def test_performer_raises_exception(self):
        class DoError(Exception):
            pass

        class EDo:
            pass

        def perform_do(intent):
            raise DoError()

        async def corofunc():
            await Effect(EDo())

        dispatcher = TypeDispatcher({
            EDo: perform_do
        })
        with pytest.raises(DoError):
            sync_perform(dispatcher, corofunc())

    def test_performer_raises_exception_and_catches_it(self):
        class DoError(Exception):
            pass

        @attr.s
        class EBadDo:
            pass

        @attr.s
        class EGoodDo:
            pass

        def perform_bad_do(intent):
            raise DoError()

        async def corofunc():
            try:
                await Effect(EBadDo())
            except DoError:
                return (await Effect(EGoodDo()))
            else:
                raise AssertionError("Didn't get notified of the exception")

        dispatcher = TypeDispatcher({
            EBadDo: perform_bad_do,
            EGoodDo: lambda intent: 'ok'
        })
        ret = sync_perform(dispatcher, corofunc())
        assert ret == 'ok'

    def test_performer_return_effect_should_not_trigger_it(self):
        @attr.s
        class EDoA:
            pass

        @attr.s
        class EDoB:
            pass

        dispatcher = TypeDispatcher({
            EDoA: lambda intent: Effect(EDoB()),
            EDoB: lambda intent: 'bar'
        })
        effect = Effect(EDoA())
        ret = sync_perform(dispatcher, effect)
        assert ret == Effect(EDoB())