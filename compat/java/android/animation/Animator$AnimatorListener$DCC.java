package android.animation;

/** Original bridge for donor desugared default-method calls.
 * The packaging tool changes DCC to the DEX companion spelling -CC.
 */
public final class Animator$AnimatorListener$DCC {
    private Animator$AnimatorListener$DCC() { }

    public static void $default$onAnimationStart(
            Animator.AnimatorListener listener, Animator animation, boolean reverse) {
        listener.onAnimationStart(animation);
    }

    public static void $default$onAnimationEnd(
            Animator.AnimatorListener listener, Animator animation, boolean reverse) {
        listener.onAnimationEnd(animation);
    }
}
