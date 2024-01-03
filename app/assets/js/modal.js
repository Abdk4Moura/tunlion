Vue.component('modal', {
  template: `
    <div class="modal">
      <div class="modal-content">
        <span class="close" @click="closeModal">&times;</span>
        <slot></slot>
      </div>
    </div>
  `
});

new Vue({
  el: '#app',
  data: {
    isModalOpen: false
  },
  methods: {
    openModal() {
      this.isModalOpen = true;
    },
    closeModal() {
      this.isModalOpen = false;
    }
  }
});
