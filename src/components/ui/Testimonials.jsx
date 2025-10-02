const Testimonials = () => {
  const testimonials = [
    { id: "t1",  rating: 5.0, text: "The interface feels modern and smooth. It saves me at least 2 hours every day when managing design tasks."},
    { id: "t2",  rating: 5.0, text: "Finally, a solution that blends speed with simplicity. My team adopted it within a week without training."},
    { id: "t3",  rating: 5.0, text: "I can track progress in real time and get a clear overview of our workflow. It feels empowering."},
    { id: "t4",  rating: 5.0, text: "Our pipeline visibility improved dramatically. I no longer need to manually track updates."},
    { id: "t5",  rating: 5.0, text: "The security-first approach gives me peace of mind. We handle sensitive data with confidence now."},
    { id: "t6",  rating: 5.0, text: "User feedback cycles are now twice as fast. It helps us test and ship features quickly."}
  ];

  React.useEffect(() => {
    const colUp = document.querySelector(".col-up");
    const colDown = document.querySelector(".col-down");
    const wrapper = document.querySelector(".testimonials-wrapper");

    if (!colUp || !colDown || !wrapper) return;

    let paused = false;
    const speed = 0.5;
    let animationId;

    const cloneCards = (container) => {
      const cards = Array.from(container.children);
      cards.forEach(card => {
        const clone = card.cloneNode(true);
        container.appendChild(clone);
      });
    };

    cloneCards(colUp);
    cloneCards(colDown);

    const getHalfHeight = (el) => {
      const children = Array.from(el.children);
      const halfCount = children.length / 2;
      let height = 0;
      for (let i = 0; i < halfCount; i++) {
        height += children[i].offsetHeight;
        if (i < halfCount - 1) height += 24; 
      }
      return height;
    };

    let y1 = 0;
    const maxScroll1 = getHalfHeight(colUp);
    const maxScroll2 = getHalfHeight(colDown);
    let y2 = -maxScroll2; 

    function animate() {
      if (!paused) {
        y1 -= speed;
        y2 += speed;

        if (Math.abs(y1) >= maxScroll1) {
          y1 = 0;
        }
        
        if (y2 >= 0) {
          y2 = -maxScroll2;
        }

        colUp.style.transform = `translateY(${y1}px)`;
        colDown.style.transform = `translateY(${y2}px)`;
      }
      animationId = requestAnimationFrame(animate);
    }

    animate();

    const handleMouseEnter = () => { paused = true; };
    const handleMouseLeave = () => { paused = false; };

    wrapper.addEventListener("mouseenter", handleMouseEnter);
    wrapper.addEventListener("mouseleave", handleMouseLeave);

    return () => {
      cancelAnimationFrame(animationId);
      wrapper.removeEventListener("mouseenter", handleMouseEnter);
      wrapper.removeEventListener("mouseleave", handleMouseLeave);
    };
  }, []);

  const renderCard = (t, index) => (
    <div key={`${t.id}-${index}`} className="card bg-neutral-900 rounded-xl p-5 shadow-md w-72 text-sm text-white flex-shrink-0">
      <div className="flex items-center mb-2 text-yellow-400">
        {"★".repeat(Math.floor(t.rating))}
        <span className="ml-2 text-secondary">{t.rating.toFixed(1)}</span>
      </div>
      <p className="text-secondary mb-3">{t.text}</p>
    </div>
  );

  return (
    <section className="py-14 px-6 bg-transparent">
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-12 max-w-7xl mx-auto items-center">
        <div className="lg:col-span-2 flex flex-col justify-center">
          <p className="text-sm text-secondary mb-2">Testimonials</p>
          <h2 className="text-2xl sm:text-3xl font-bold text-white mb-4 leading-snug">
            What our users are saying
          </h2>
          <p className="text-secondary text-sm">
            We continuously listen to our community and improve every day.
          </p>
        </div>

        <div className="lg:col-span-3 testimonials-wrapper flex gap-6 overflow-hidden relative h-[420px]">
          <div className="pointer-events-none absolute top-0 left-0 w-full h-16 bg-gradient-to-b from-[#1f1f1f]/90 to-transparent z-20"></div>
          <div className="pointer-events-none absolute bottom-0 left-0 w-full h-16 bg-gradient-to-t from-[#1f1f1f]/90 to-transparent z-20"></div>

          <div className="col-up flex flex-col gap-6">
            {testimonials.map((t, i) => renderCard(t, i))}
          </div>

          <div className="col-down flex flex-col gap-6">
            {testimonials.map((t, i) => renderCard(t, i))}
          </div>
        </div>
      </div>
    </section>
  );
};

window.Testimonials = Testimonials;
