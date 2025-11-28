<script>
export default {
    props: ['title'],
    data() {
        return {
            
        }
    },
    methods: {

    },
    
    mounted() {
        
    },
}
</script>

<template>
    <div class="container my-5 bg-body-tertiary rounded-3 p-5 d-flex flex-column align-items-center">
        <div class="d-flex align-items-center gap-3">
            <img src="../../assets/logo.png" id="logo">
            <h5 class="text-muted">
                |
            </h5>
            <h1 class="display-5 fw-bold">
                Энтропия файла НГУЭУ
            </h1>
        </div>

        <p class="mx-auto fs-5 text-muted m-0 p-0 mb-3">
            Cервис удобной и быстрой проверки количества одинаковых символов в файле
        </p>


        <div class="w-100">
            <slot></slot>
        </div>
    </div>
</template>

<style>
#avatar {
    width: 110px;
}

#logo {
    width: 50px;
}
</style>