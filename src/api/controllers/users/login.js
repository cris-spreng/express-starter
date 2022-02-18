const Bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv').config();

// Cargamos nuestro modelo
const User = require('../../models/user');
// Cargamos nuestras variables de entorno

module.exports = async ({ body }, res) => {
    
    const { password, username } = body;

    try {
    // Buscamos el usuario
        const userRecord = await User.findOne({ username });

        if(userRecord){
            if(Bcrypt.compareSync(password, userRecord.password)){
                const token = jwt.sign(
                    // Es importante que se note, que utilizamos el
                    // usuario que ya buscamos en la base de datos
                    // y el "_id" en vez de "id"
                    { email: userRecord.email, id: userRecord._id, username },
                    process.env.API_KEY,
                    { expiresIn: process.env.TOKEN_EXPIRES_IN },
                );
                return res.status(200).json({ token });          
            }
        }

        return res.status(401).json({
            status: 401,
            message: '¡Tu email o contraseña son incorrectos, por favor, veríficalo!',
        });
    } catch (error) {
          // Este error se genera si se procesa mal la solicitud
          // en la base de datos
        return res.status(400).json({
            status: 400,
            message: error,
        });
    }
};